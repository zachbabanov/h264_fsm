/*
* @license
* (C) zachbabanov
*
*/

#include <encoder.hpp>
#include <logger.hpp>
#include <common.hpp>

#include <algorithm>
#include <cstring>
#include <cassert>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>

// We need gf operations from rs implementation
#include <gf.hpp>

using namespace project::common;
using namespace project::fec;
using namespace project::log;

/*
 * We'll implement cross-fragment systematic RS encoding/decoding over GF(256).
 *
 * Layout:
 *  - Header (network-order) [FecPacketHeader]
 *  - Payload: fragments * frag_size bytes, where fragments = fec_k + fec_m,
 *             frag_size = ceil(orig_len / fec_k) (each fragment padded with zeros)
 *
 * Encoding:
 *  - first fec_k fragments are systematic data fragments (sized frag_size)
 *  - next fec_m fragments are parity fragments computed as linear combinations
 *    of data fragments using evaluation points alpha^(p+1) for parity row p.
 *
 * Decoding:
 *  - fast path: if all first fec_k fragments present, copy their bytes and trim to orig_len
 *  - otherwise: we know which fragments present (bitmap) -> select any k present fragments
 *    whose encoding matrix is invertible -> invert matrix and recover original data fragments.
 */

// network conversions helpers (reuse from previous version)
static uint16_t h16(uint16_t v) { return hton_u16(v); }
static uint32_t h32(uint32_t v) { return hton_u32(v); }
static uint64_t h64(uint64_t v) { return hton_u64(v); }
static uint16_t n16(uint16_t v) { return ntoh_u16(v); }
static uint32_t n32(uint32_t v) { return ntoh_u32(v); }
static uint64_t n64(uint64_t v) { return ntoh_u64(v); }

/**
 * Hex-dump helper (first N bytes)
 */
static std::string hexdump_prefix(const char *data, size_t len, size_t max_bytes = 64) {
    size_t n = std::min(len, max_bytes);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        unsigned int b = (unsigned char)data[i];
        ss << std::setw(2) << b;
        if (i + 1 < n) ss << " ";
    }
    if (len > n) ss << " ... (+" << (len - n) << " bytes)";
    ss << std::dec;
    return ss.str();
}

/**
 * Build a wire-ready packet: header (network order) + payload (encoded bytes).
 *
 * Systematic cross-fragment RS encoding (over GF(256)), using primitive 2 as alpha.
 */
std::vector<char> StubFec::encode_with_header(uint32_t client_id,
                                              uint32_t packet_seq,
                                              uint16_t fec_k,
                                              uint16_t fec_m,
                                              uint16_t flags,
                                              uint64_t pts,
                                              const char *data,
                                              size_t len) {
    auto t0 = std::chrono::high_resolution_clock::now();

    if (fec_k == 0) fec_k = 1; // sanitize
    // compute fragment data length (per data-fragment)
    size_t frag_data_len = (len + (size_t)fec_k - 1) / (size_t)fec_k;
    if (frag_data_len == 0) frag_data_len = 1;

    uint16_t total_frags = (uint16_t)((size_t)fec_k + (size_t)fec_m);
    size_t encoded_payload_len = (size_t)total_frags * frag_data_len;

    // prepare header (network byte order)
    FecPacketHeader hdr{};
    hdr.client_id = h32(client_id);
    hdr.packet_seq = h32(packet_seq);
    hdr.fec_k = h16(fec_k);
    hdr.fec_m = h16(fec_m);
    hdr.flags = h16(flags);
    hdr.fragments = h16(total_frags);
    hdr.payload_len = h32((uint32_t)encoded_payload_len);
    hdr.orig_len = h32((uint32_t)len);
    hdr.pts = h64(pts);

    std::vector<char> out;
    out.resize(FEC_PACKET_HEADER_SIZE + encoded_payload_len);
    std::memcpy(out.data(), &hdr, FEC_PACKET_HEADER_SIZE);

    // Organize data into fec_k data fragments each of frag_data_len (pad zeros)
    std::vector<std::vector<uint8_t>> data_frags(fec_k, std::vector<uint8_t>(frag_data_len, 0));
    for (uint16_t d = 0; d < fec_k; ++d) {
        size_t offset = (size_t)d * frag_data_len;
        if (offset < len) {
            size_t take = std::min((size_t)frag_data_len, len - offset);
            std::memcpy(data_frags[d].data(), data + offset, take);
            // remaining already zero-padded
        }
    }

    // Copy systematic data fragments into output payload area
    size_t written = 0;
    for (uint16_t d = 0; d < fec_k; ++d) {
        std::memcpy(out.data() + FEC_PACKET_HEADER_SIZE + written, (char*)data_frags[d].data(), frag_data_len);
        written += frag_data_len;
    }

    // If no parity requested, we're done
    if (fec_m == 0) {
        auto t1 = std::chrono::high_resolution_clock::now();
        double encode_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();
        LOG_FEC_INFO("encode_with_header: client_id={} seq={} fec_k={} fec_m={} pts={} orig_payload_len={} fragments={} encoded_len={} total_packet={} encode_time_ms={:.3f}",
                     client_id, packet_seq, fec_k, fec_m, pts, (uint32_t)len, (unsigned)total_frags, (uint32_t)encoded_payload_len, (uint32_t)out.size(), encode_ms);

        if (encoded_payload_len > 0) {
            std::string hd = hexdump_prefix(out.data() + FEC_PACKET_HEADER_SIZE, std::min((size_t)64, encoded_payload_len), 32);
            LOG_FEC_DEBUG("encode_with_header: first_encoded_fragment_hex={}", hd.c_str());
        }
        return out;
    }

    // Compute parity fragments:
    // For parity p (0..m-1) and data fragment d (0..k-1) coefficient = alpha^{(p+1)*d}
    // where alpha = 2 (primitive element in gf tables)
    // parity[p][b] = xor_d gf_mul(data_frags[d][b], coeff(d,p))
    for (uint16_t p = 0; p < fec_m; ++p) {
        std::vector<uint8_t> parity(frag_data_len, 0);
        for (uint16_t d = 0; d < fec_k; ++d) {
            // compute coefficient = alpha^{(p+1)*d}
            uint8_t coeff = RS::gf::pow(2, (intmax_t)((size_t)(p + 1) * d));
            if (coeff == 0) {
                // multiplication by 0 -> skip
                continue;
            }
            for (size_t b = 0; b < frag_data_len; ++b) {
                uint8_t val = data_frags[d][b];
                if (val != 0) {
                    parity[b] ^= RS::gf::mul(val, coeff);
                }
            }
        }
        // append parity fragment to output
        std::memcpy(out.data() + FEC_PACKET_HEADER_SIZE + written, (char*)parity.data(), frag_data_len);
        written += frag_data_len;
    }

    assert(written == encoded_payload_len);

    auto t1 = std::chrono::high_resolution_clock::now();
    double encode_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();
    LOG_FEC_INFO("encode_with_header: client_id={} seq={} fec_k={} fec_m={} pts={} orig_payload_len={} fragments={} encoded_len={} total_packet={} encode_time_ms={:.3f}",
                 client_id, packet_seq, fec_k, fec_m, pts, (uint32_t)len, (unsigned)total_frags, (uint32_t)encoded_payload_len, (uint32_t)out.size(), encode_ms);

    if (encoded_payload_len > 0) {
        std::string hd = hexdump_prefix(out.data() + FEC_PACKET_HEADER_SIZE, std::min((size_t)64, encoded_payload_len), 32);
        LOG_FEC_DEBUG("encode_with_header: first_encoded_fragment_hex={}", hd.c_str());
    }

    return out;
}

/**
 * Parse wire header into host-order header.
 */
FecPacketHeader StubFec::parse_header(const char *hdr_bytes, size_t hdr_len) {
    FecPacketHeader net{};
    FecPacketHeader host{};
    if (hdr_len < FEC_PACKET_HEADER_SIZE) return host;
    std::memcpy(&net, hdr_bytes, FEC_PACKET_HEADER_SIZE);
    host.client_id = n32(net.client_id);
    host.packet_seq = n32(net.packet_seq);
    host.fec_k = n16(net.fec_k);
    host.fec_m = n16(net.fec_m);
    host.flags = n16(net.flags);
    host.fragments = n16(net.fragments);
    host.payload_len = n32(net.payload_len);
    host.orig_len = n32(net.orig_len);
    host.pts = n64(net.pts);
    return host;
}

/**
 * Utility: try fast-path (all first fec_k fragments present)
 */
static bool all_data_fragments_present(const std::vector<uint8_t> &present, uint16_t fec_k) {
    if (present.size() < (size_t)fec_k) return false;
    for (uint16_t i = 0; i < fec_k; ++i) {
        if (!present[i]) return false;
    }
    return true;
}

/**
 * Gaussian elimination to invert square matrix (k x k) over GF(256).
 * Input: A (k x k) as vector<vector<uint8_t>>
 * Output: inverse matrix invA (k x k). Returns true on success (invertible).
 */
static bool invert_matrix_gf(std::vector<std::vector<uint8_t>> A, std::vector<std::vector<uint8_t>> &inv) {
    size_t n = A.size();
    inv.assign(n, std::vector<uint8_t>(n, 0));
    // initialize inv to identity
    for (size_t i = 0; i < n; ++i) inv[i][i] = 1;

    for (size_t col = 0; col < n; ++col) {
        // find pivot row with A[row][col] != 0
        size_t pivot = col;
        while (pivot < n && A[pivot][col] == 0) ++pivot;
        if (pivot == n) return false; // singular

        if (pivot != col) {
            std::swap(A[pivot], A[col]);
            std::swap(inv[pivot], inv[col]);
        }

        uint8_t pivot_val = A[col][col];
        // normalize pivot to 1
        if (pivot_val != 1) {
            uint8_t inv_pivot = RS::gf::inverse(pivot_val);
            for (size_t j = 0; j < n; ++j) {
                A[col][j] = RS::gf::mul(A[col][j], inv_pivot);
                inv[col][j] = RS::gf::mul(inv[col][j], inv_pivot);
            }
        }

        // eliminate other rows
        for (size_t row = 0; row < n; ++row) {
            if (row == col) continue;
            uint8_t factor = A[row][col];
            if (factor == 0) continue;
            // row = row - factor * col  (in GF subtraction == xor)
            for (size_t j = 0; j < n; ++j) {
                uint8_t prod = RS::gf::mul(factor, A[col][j]);
                A[row][j] ^= prod;
                uint8_t prod2 = RS::gf::mul(factor, inv[col][j]);
                inv[row][j] ^= prod2;
            }
        }
    }
    return true;
}

/**
 * Decode payload given payload bytes and a bitmap of which fragments are present.
 *
 * fec_k, fec_m are numbers of data/parity fragments (host order).
 * fragments == fec_k + fec_m (total fragments in payload).
 *
 * frag_present: vector<uint8_t> of length 'fragments', elements 0/1 indicating presence.
 *
 * Returns reconstructed original payload of length orig_len, or empty vector on failure.
 */
std::vector<char> StubFec::decode_payload(const char *data, size_t len, uint16_t fragments, uint32_t orig_len,
                                          uint16_t fec_k, uint16_t fec_m, const std::vector<uint8_t> &frag_present) {
    std::vector<char> out;
    size_t total_frags = (size_t)fragments;
    if (total_frags == 0) return out;
    if ((size_t)fec_k + (size_t)fec_m != total_frags) {
        LOG_FEC_ERROR("decode_payload: header mismatch fec_k+fec_m != fragments ({}+{} != {})", fec_k, fec_m, fragments);
        return out;
    }
    if (len < total_frags) {
        LOG_FEC_ERROR("decode_payload: payload too short");
        return out;
    }
    size_t frag_size = len / total_frags;
    if (frag_size * total_frags != len) {
        LOG_FEC_ERROR("decode_payload: payload length not divisible by fragments: len={} frags={}", (uint32_t)len, (unsigned)total_frags);
        return out;
    }

    // Quick path: if first fec_k data fragments all present -> reconstruct by concatenation (systematic)
    if (all_data_fragments_present(frag_present, fec_k)) {
        out.reserve((size_t)orig_len);
        for (uint16_t d = 0; d < fec_k; ++d) {
            const unsigned char *frag_ptr = (const unsigned char*)(data + (size_t)d * frag_size);
            size_t remaining = (size_t)orig_len - out.size();
            size_t take = std::min(remaining, frag_size);
            if (take) {
                out.insert(out.end(), (const char*)frag_ptr, (const char*)frag_ptr + take);
            }
            if (out.size() >= orig_len) break;
        }
        if (out.size() < orig_len) {
            LOG_FEC_WARN("decode_payload: fast-path produced {} bytes but orig_len={} (fragments={}) - stream may be truncated",
                         (uint32_t)out.size(), orig_len, (unsigned)fragments);
        } else {
            LOG_FEC_DEBUG("decode_payload: decoded_len={} orig_len={} fragments={}", (uint32_t)out.size(), orig_len, (unsigned)fragments);
        }
        return out;
    }

    // Otherwise, perform erasure decoding.
    // Build array of received fragment indices
    std::vector<size_t> present_idx;
    present_idx.reserve(total_frags);
    for (size_t i = 0; i < total_frags; ++i) {
        if (i < frag_present.size() && frag_present[i]) present_idx.push_back(i);
    }

    if (present_idx.size() < (size_t)fec_k) {
        LOG_FEC_ERROR("decode_payload: insufficient fragments present to reconstruct: have={} need={}", (unsigned)present_idx.size(), fec_k);
        return out;
    }

    // Choose k rows (fragment indices) to build kxk matrix A. Prefer to include data fragments when possible.
    // We'll try to pick k indices from present_idx that yield an invertible matrix; try greedy selection with fallback.
    std::vector<size_t> chosen;
    chosen.reserve(fec_k);
    // first, select all present data fragments
    for (size_t idx : present_idx) {
        if (idx < fec_k) chosen.push_back(idx);
        if (chosen.size() == (size_t)fec_k) break;
    }
    // then fill with parity fragments as needed
    if (chosen.size() < (size_t)fec_k) {
        for (size_t idx : present_idx) {
            if (idx >= fec_k) {
                chosen.push_back(idx);
                if (chosen.size() == (size_t)fec_k) break;
            }
        }
    }

    // If chosen rows are not invertible, attempt simple replacement search among present rows (limited tries)
    auto build_matrix = [&](const std::vector<size_t> &rows) {
        std::vector<std::vector<uint8_t>> A(rows.size(), std::vector<uint8_t>(fec_k));
        for (size_t r = 0; r < rows.size(); ++r) {
            size_t frag_index = rows[r];
            if (frag_index < fec_k) {
                // systematic: unit vector with 1 at column frag_index
                for (uint16_t c = 0; c < fec_k; ++c) A[r][c] = (c == frag_index) ? 1 : 0;
            } else {
                // parity row p = frag_index - fec_k
                uint16_t p = (uint16_t)(frag_index - fec_k);
                for (uint16_t c = 0; c < fec_k; ++c) {
                    // coeff = alpha^{(p+1)*c}
                    A[r][c] = RS::gf::pow(2, (intmax_t)((size_t)(p + 1) * c));
                }
            }
        }
        return A;
    };

    bool found = false;
    std::vector<std::vector<uint8_t>> invA;
    // Try initial chosen
    {
        auto A = build_matrix(chosen);
        if (invert_matrix_gf(A, invA)) {
            found = true;
        }
    }
    // If not invertible, brute-force try swapping some rows from present_idx (limited)
    if (!found) {
        // Build list of candidate rows (present_idx)
        std::vector<size_t> candidates = present_idx;
        // We will try combinations by replacing up to 3 positions greedily (to avoid combinatorial explosion).
        // For practical stream sizes this should be enough. If still not found, bail out.
        size_t max_replace = std::min<size_t>(3, fec_k);
        bool stop = false;
        for (size_t rpos = 0; rpos < fec_k && !found && !stop; ++rpos) {
            for (size_t cand : candidates) {
                // skip if cand already in chosen
                if (std::find(chosen.begin(), chosen.end(), cand) != chosen.end()) continue;
                auto tmp = chosen;
                tmp[rpos] = cand;
                auto A = build_matrix(tmp);
                if (invert_matrix_gf(A, invA)) {
                    chosen = tmp;
                    found = true;
                    break;
                }
            }
        }
    }

    if (!found) {
        LOG_FEC_ERROR("decode_payload: failed to find invertible matrix for reconstruction (k={} m={} present={})", fec_k, fec_m, present_idx.size());
        return out;
    }

    // Now chosen holds k fragment indices and invA is k x k inverse matrix over GF.
    // We'll compute original data fragments (k fragments) by: data = invA * y, where y is vector of length k containing
    // bytes from the chosen fragments at given offset.
    // For efficiency, we compute for each byte offset b separately.

    // Prepare storage for recovered data fragments
    std::vector<std::vector<uint8_t>> recovered(fec_k, std::vector<uint8_t>(frag_size, 0));

    // For each byte position b in 0..frag_size-1, form y[r] = fragment[ chosen[r] ][b]
    for (size_t b = 0; b < frag_size; ++b) {
        // build y
        std::vector<uint8_t> y(fec_k);
        for (size_t r = 0; r < (size_t)fec_k; ++r) {
            size_t frag_index = chosen[r];
            const unsigned char *frag_ptr = (const unsigned char*)(data + frag_index * frag_size);
            y[r] = frag_ptr[b];
        }
        // compute x = invA * y  (x length k)
        std::vector<uint8_t> x(fec_k, 0);
        for (size_t i = 0; i < (size_t)fec_k; ++i) {
            uint8_t acc = 0;
            for (size_t j = 0; j < (size_t)fec_k; ++j) {
                if (invA[i][j] != 0 && y[j] != 0) {
                    acc ^= RS::gf::mul(invA[i][j], y[j]);
                }
            }
            x[i] = acc;
        }
        // write x into recovered column b across recovered fragments
        for (size_t i = 0; i < (size_t)fec_k; ++i) {
            recovered[i][b] = x[i];
        }
    }

    // Compose output by concatenating recovered[0..k-1] and trimming to orig_len
    out.reserve(orig_len);
    for (uint16_t d = 0; d < fec_k; ++d) {
        size_t take = std::min((size_t)orig_len - out.size(), frag_size);
        if (take) {
            out.insert(out.end(), (const char*)recovered[d].data(), (const char*)recovered[d].data() + take);
        }
        if (out.size() >= orig_len) break;
    }

    if (out.size() < orig_len) {
        LOG_FEC_WARN("decode_payload: reconstructed only {} bytes but orig_len={}", (uint32_t)out.size(), orig_len);
    } else {
        LOG_FEC_DEBUG("decode_payload: successfully reconstructed orig_len={} (fragments={} k={} m={})",
                      orig_len, fragments, fec_k, fec_m);
    }

    return out;
}

/**
 * Overload: decode_payload without fragment bitmap -> assume all present (fast-path).
 */
std::vector<char> StubFec::decode_payload(const char *data, size_t len, uint16_t fragments, uint32_t orig_len) {
    // We don't have fec_k/fec_m in this signature, but header parse + decode_packet uses this path only when reading the whole packet.
    // For backwards compat, treat as all fragments present and reconstruct by copying sequentially until orig_len.
    std::vector<char> out;
    if (fragments == 0) return out;
    size_t frag_size = len / fragments;
    out.reserve(orig_len);
    for (uint16_t i = 0; i < fragments; ++i) {
        size_t remaining = (size_t)orig_len - out.size();
        size_t take = std::min(remaining, frag_size);
        if (take) {
            const unsigned char *frag_ptr = (const unsigned char*)(data + (size_t)i * frag_size);
            out.insert(out.end(), (const char*)frag_ptr, (const char*)frag_ptr + take);
        }
        if (out.size() >= orig_len) break;
    }
    return out;
}

/**
 * Decode full packet (header + payload) and return structured data.
 * This version assumes the assembled packet contains the header + payload bytes, and that
 * **all fragments are present** (legacy behavior). Use server-side direct call to decode_payload(payload, len, fragments, orig_len, fec_k, fec_m, frag_present)
 * to pass actual bitmap when some fragments missing.
 */
FecPacket StubFec::decode_packet(const char *packet_bytes, size_t packet_len) {
    FecPacket pkt{};
    if (packet_len < (int)FEC_PACKET_HEADER_SIZE) return pkt;
    FecPacketHeader hdr = parse_header(packet_bytes, FEC_PACKET_HEADER_SIZE);
    pkt.client_id = hdr.client_id;
    pkt.packet_seq = hdr.packet_seq;
    pkt.fec_k = hdr.fec_k;
    pkt.fec_m = hdr.fec_m;
    pkt.flags = hdr.flags;
    pkt.fragments = hdr.fragments;
    pkt.orig_len = hdr.orig_len;
    pkt.pts = hdr.pts;

    size_t payload_len = hdr.payload_len;
    size_t total_needed = FEC_PACKET_HEADER_SIZE + payload_len;
    if ((size_t)packet_len < total_needed) {
        LOG_FEC_DEBUG("decode_packet: incomplete expected={} have={}", (uint32_t)total_needed, (uint32_t)packet_len);
        return pkt;
    }
    const char *payload_ptr = packet_bytes + FEC_PACKET_HEADER_SIZE;

    auto t0 = std::chrono::high_resolution_clock::now();
    // assume all fragments present
    pkt.payload = decode_payload(payload_ptr, payload_len, hdr.fragments, hdr.orig_len);
    auto t1 = std::chrono::high_resolution_clock::now();
    double decode_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();

    LOG_FEC_INFO("decode_packet: client_id={} seq={} fec_k={} fec_m={} pts={} payload_len(encoded)={} decoded_payload_len={} fragments={} decode_time_ms={:.3f}",
                 pkt.client_id, pkt.packet_seq, pkt.fec_k, pkt.fec_m, pkt.pts, (uint32_t)payload_len, (uint32_t)pkt.payload.size(), (unsigned)hdr.fragments, decode_ms);

    return pkt;
}
