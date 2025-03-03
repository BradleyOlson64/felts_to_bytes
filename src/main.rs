use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::RngCore;
use starknet_crypto::Felt;

#[derive(Debug, Clone, PartialEq)]
struct Segment {
    offset: u64,
    size: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct ResultSegment {
    offset: u64,
    bytes: Vec<u8>,
}

fn main() {
    // 1. Generate a random buffer of 16KB
    let buffer = generate_random_buffer();
    println!("Buffer length: {} bytes", buffer.len());

    // 2. Generate random layout segments with diverse sizes
    let segments = generate_random_layout_segments(buffer.len());
    println!("Generated {} segments with diverse sizes:", segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let category = if seg.size < 31 {
            "<31 bytes"
        } else if seg.size == 31 {
            "exactly 31 bytes"
        } else if seg.size < 62 {
            "32-61 bytes"
        } else {
            ">=62 bytes"
        };
        println!(
            "  Segment {}: offset={} size={} ({})",
            i, seg.offset, seg.size, category
        );
    }

    // 3. Sanitize layout segments
    let sanitized = sanitize(&segments);

    // 4. Convert byte-based segments into felt-based offsets and sizes (31-byte alignment)
    let felt_ranges = convert_ranges_to_felt_ranges(&sanitized);
    println!("\nConverted to felt ranges (31-byte aligned):");
    for (i, fr) in felt_ranges.iter().enumerate() {
        println!(
            "  Felt range {}: felt_offset={} felt_count={}",
            i, fr.offset, fr.size
        );
    }

    // 5. Extract raw byte segments from the buffer according to the original layout
    let original_segments_data = extract_ranges_from_bytes(&buffer, &segments);
    println!("\n Extracted original segments from buffer:");
    for (i, seg) in original_segments_data.iter().enumerate() {
        println!("  Segment {}: {:?}", i, hex::encode(seg.bytes.clone()));
    }

    // 6. Convert the entire buffer into an array of 31-byte felts (pad with 0x00 if needed)
    let felt_array = convert_buffer_to_felt_array(&buffer);
    println!(
        "\nConverted buffer to {} felts of 31 bytes",
        felt_array.len()
    );

    // 7. Retrieve felt-aligned ranges from the felt array based on the felt ranges
    let felt_segments_data = extract_felt_ranges_from_felt_array(&felt_array, &felt_ranges);
    println!("Extracted felt-aligned segments from felt array:");
    for (i, felt_seg) in felt_segments_data.iter().enumerate() {
        let felt_count = felt_seg.len();
        let bytes_covered = felt_count * 31;

        println!(
            "  Segment {}: {} felts (covers {} bytes including padding) : {:?}",
            i,
            felt_count,
            bytes_covered,
            //felt_seg,
            felt_seg
                .iter()
                .map(|f| format!("0x{}", hex::encode(f.to_bytes_be())))
                .collect::<Vec<_>>()
        );
    }

    // 8. Convert felt-aligned extracted data back into the sanitized byte-based segments
    let reconstructed_segments_data =
        extract_bytes_from_felt_array_using_original_ranges(&felt_segments_data, &sanitized);

    // 9. Convert sanitized segments into result segments with original layout
    let final_result_segments = extract_original_byte_ranges_from_sanitized(reconstructed_segments_data, &segments);

    // 10. Verify that the reconstructed byte segments match the original segments
    println!("\nVerification of reconstructed segments:");
    for (i, orig_bytes) in original_segments_data.iter().enumerate() {
        let reconstructed_bytes = &final_result_segments[i];
        let result = if orig_bytes.bytes == *reconstructed_bytes.bytes {
            "OK"
        } else {
            "MISMATCH"
        };
        println!(
            "  Segment {} reconstruction {} ({} bytes) {:?} {:?}",
            i,
            result,
            segments[i].size,
            hex::encode(orig_bytes.bytes.clone()),
            hex::encode(reconstructed_bytes.bytes.clone())
        );
        assert_eq!(
            orig_bytes.bytes, *reconstructed_bytes.bytes,
            "Segment {} data mismatch",
            i
        );
    }
    println!("All segments reconstructed correctly.");
}

// 1. generate_random_buffer(): Generates a 16KB buffer of random bytes.
fn generate_random_buffer() -> Vec<u8> {
    let size = 16 * 1024; // 16 KB
    let mut buffer = vec![0u8; size];
    // Fill the buffer with random bytes
    thread_rng().fill_bytes(&mut buffer);
    buffer
}

#[allow(unused)]
// 2a. generate_sequential_layout_segments(): Generates segments with diverse sizes.
fn generate_sequential_layout_segments(buffer_len: usize) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();
    // Define size categories
    let size_small = (thread_rng().next_u32() % 30 + 1) as u64; // 1..30 bytes
    let size_exact = 31u64; // exactly 31 bytes
    let size_mid = (thread_rng().next_u32() % 30 + 32) as u64; // 32..61 bytes
    let size_large = (thread_rng().next_u32() % 939 + 62) as u64; // 62..1000 bytes

    // Divide buffer into four regions to avoid overlap between segments
    let quarter = buffer_len / 4;
    let base0 = 0;
    let base1 = quarter;
    let base2 = quarter * 2;
    let base3 = quarter * 3;

    // Helper to pick an offset within a region such that the segment fits
    let mut rng = thread_rng();
    let mut pick_offset = |base: usize, size: u64| -> u64 {
        assert!(size < quarter as u64); // Segments will potentially overlap if they are larger than their regions.
                                        // End of this region (or buffer end, whichever is smaller)
        let region_end = (base + quarter).min(buffer_len);
        // If segment doesn't fit in remaining buffer from base, clamp it to end
        if (base as u64) + size > buffer_len as u64 {
            return (buffer_len as u64).saturating_sub(size);
        }
        // Pick a random offset in [base, max_offset] where segment fits entirely
        let max_offset = region_end.saturating_sub(size as usize);
        let off_within = rng.next_u32() as usize % ((max_offset - base) + 1);
        (base + off_within) as u64
    };

    // Generate one segment in each category region + 1 segment at start and 1 segment at end
    segments.push(Segment {
        offset: 0,
        size: 20,
    });

    let off_small = pick_offset(base0, size_small);
    segments.push(Segment {
        offset: off_small,
        size: size_small,
    });

    let off_exact = pick_offset(base1, size_exact);
    segments.push(Segment {
        offset: off_exact,
        size: size_exact,
    });

    let off_mid = pick_offset(base2, size_mid);
    segments.push(Segment {
        offset: off_mid,
        size: size_mid,
    });

    let off_large = pick_offset(base3, size_large);
    segments.push(Segment {
        offset: off_large,
        size: size_large,
    });

    // the tail end but more than one felt
    segments.push(Segment {
        offset: buffer_len as u64 - 42,
        size: 42,
    });

    return segments;
}

//2b. Generates 6 layout segments of varying lengths. Two of these segments touch each end of the provided buffer.
//    The other 4 segments are generated randomly, but in such a way so that they aren't already in the correct order
//    And so that at least two of the segments overlap
fn generate_random_layout_segments(buffer_len: usize) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();

    // Get segment sizes
    let size_small = (thread_rng().next_u32() % 30 + 1) as u64; // 1..30 bytes
    let size_exact = 31u64; // exactly 31 bytes
    let size_mid = (thread_rng().next_u32() % 30 + 32) as u64; // 32..61 bytes
    let size_large = (thread_rng().next_u32() % 939 + 62) as u64; // 62..1000 bytes

    // Generate one segment in each category region + 1 segment at start and 1 segment at end
    segments.push(Segment {
        offset: 0,
        size: 20,
    });

    // Start first small segment in the middle of first segment. Makes sure the first and second segments overlap.
    let off_overlapping = thread_rng().next_u64() % 20;
    segments.push(Segment {
        offset: off_overlapping,
        size: size_small,
    });

    let off_small = (thread_rng().next_u64() % buffer_len as u64).saturating_sub(size_small);
    segments.push(Segment {
        offset: off_small,
        size: size_small,
    });

    let off_exact = (thread_rng().next_u64() % buffer_len as u64).saturating_sub(size_exact);
    segments.push(Segment {
        offset: off_exact,
        size: size_exact,
    });

    let off_mid = (thread_rng().next_u64() % buffer_len as u64).saturating_sub(size_mid);
    segments.push(Segment {
        offset: off_mid,
        size: size_mid,
    });

    let off_large = (thread_rng().next_u64() % buffer_len as u64).saturating_sub(size_large);
    segments.push(Segment {
        offset: off_large,
        size: size_large,
    });

    // the tail end but more than one felt
    segments.push(Segment {
        offset: buffer_len as u64 - 42,
        size: 42,
    });

    // Randomize ordering. Sanitizing step should re-order.
    segments.shuffle(&mut thread_rng());

    segments
}

//3. Sanitize layout segments
fn sanitize(segments: &[Segment]) -> Vec<Segment> {
    // Sort segments in order of least to greatest offset
    let mut sanitized = segments.to_vec();
    sanitized.sort_by(|seg_a, seg_b| {
        seg_a.offset.cmp(&seg_b.offset)
    });

    // Condense segments pair by pair starting from end. We start with i = sanitized.len() - 2 
    // because the last pair of segment indices is (len - 2, len - 1)
    let mut i = sanitized.len() - 2;
    loop {
        let left_segment = &sanitized[i];
        let right_segment = &sanitized[i + 1];

        // Immediately adjacent counts as overlapping for our purposes. Therefore `right_segment.offset - 1`
        let overlapping = (left_segment.offset + left_segment.size) >= right_segment.offset - 1;
        if overlapping {
            let first_byte_index = left_segment.offset.min(right_segment.offset);
            let last_byte_index = (left_segment.offset + left_segment.size).max(right_segment.offset + right_segment.size) - 1;
            let new_segment = Segment{ offset: first_byte_index, size: last_byte_index - first_byte_index + 1};
            // Replace two combined segments with new segment
            sanitized.remove(i + 1);
            sanitized[i] = new_segment;
        } 
        // Proceed to next pair or break if this was the last pair
        if i == 0 { break; }
        i -= 1;
    }

    sanitized
}

//4. convert_ranges_to_felt_ranges(): Converts byte segments into felt-based ranges (31-byte units).
fn convert_ranges_to_felt_ranges(segments: &[Segment]) -> Vec<Segment> {
    let mut felt_ranges = Vec::with_capacity(segments.len());
    for seg in segments {
        // Inclusive last byte index of the segment
        let last_byte_index = seg.offset + seg.size - 1;
        // Felt index at start and end of the segment
        let felt_offset = seg.offset / 31;
        let felt_end = last_byte_index / 31;
        // Number of 31-byte felts needed to cover this segment
        let felt_count = felt_end - felt_offset + 1;
        felt_ranges.push(Segment {
            offset: felt_offset,
            size: felt_count,
        });
    }
    return felt_ranges;
}

// 5. extract_ranges_from_bytes(): Extracts raw byte segments from the buffer.
fn extract_ranges_from_bytes(buffer: &[u8], segments: &[Segment]) -> Vec<ResultSegment> {
    let mut extracted_data = Vec::with_capacity(segments.len());
    for seg in segments {
        let start = seg.offset as usize;
        let end = (start + seg.size as usize).min(buffer.len());
        // Slice the buffer for this segment and collect the bytes
        let segment_bytes = buffer[start..end].to_vec();
        extracted_data.push(ResultSegment{ offset: seg.offset, bytes: segment_bytes});
    }
    return extracted_data;
}

// 8. extract_felt_ranges_from_felt_array(): Gets the 31-byte felt chunks for each felt range.
fn extract_felt_ranges_from_felt_array(
    felt_array: &[Felt],
    felt_ranges: &[Segment],
) -> Vec<Vec<Felt>> {
    let mut extracted_felt_segments = Vec::with_capacity(felt_ranges.len());

    for range in felt_ranges {
        let start_index = range.offset as usize;
        let count = range.size as usize;
        let end_index = start_index + count;

        // Collect the felt chunks covering this range
        let segment_felts = felt_array[start_index..end_index].to_vec();
        extracted_felt_segments.push(segment_felts);
    }

    extracted_felt_segments
}

// Converts the buffer into a vector of 31-byte Felt values, ensuring leading zero padding.
fn convert_buffer_to_felt_array(buffer: &[u8]) -> Vec<Felt> {
    buffer
        .chunks(31)
        .map(|chunk| {
            let mut padded_chunk = [0u8; 32]; // Always 32 bytes
            padded_chunk[1..1 + chunk.len()].copy_from_slice(chunk); // Right-align 31-byte chunk
            padded_chunk[0] = 0x00; // Explicitly ensure the first byte is zero
            Felt::from_bytes_be(&padded_chunk)
        })
        .collect()
}

// Reconstructs original byte segments from felt-aligned data.
fn extract_bytes_from_felt_array_using_original_ranges(
    felt_segments: &[Vec<Felt>],
    original_segments: &[Segment],
) -> Vec<ResultSegment> {
    original_segments
        .iter()
        .enumerate()
        .map(|(i, orig)| {
            let mut combined_bytes = Vec::with_capacity(felt_segments[i].len() * 31);
            for felt in &felt_segments[i] {
                let felt_bytes = felt.to_bytes_be(); // Get 32 bytes
                combined_bytes.extend_from_slice(&felt_bytes[1..]); // Skip first byte (padding)
            }

            let start = (orig.offset % 31) as usize;
            let end = start + orig.size as usize;
            ResultSegment {
                offset: orig.offset,
                bytes: combined_bytes[start..end].to_vec()
            }
        })
        .collect()
}

fn extract_original_byte_ranges_from_sanitized(sanitized_results: Vec<ResultSegment>, original_segments: &[Segment]) -> Vec<ResultSegment> {
    let mut result: Vec<ResultSegment> = Vec::with_capacity(original_segments.len());
    for orig in original_segments {
        let mut collected_bytes: Vec<u8> = Vec::with_capacity(orig.size as usize);
        let mut collected_up_to: usize = orig.offset as usize;
        for sanitized in &sanitized_results {
            let last_sanitized_byte_idx = sanitized.offset as usize + sanitized.bytes.len() - 1;
            // If part of original segment range is contained in sanitized segment, then copy bytes over
            if sanitized.offset as usize <= collected_up_to && last_sanitized_byte_idx >= collected_up_to {
                let last_orig_seg_idx = (orig.offset + orig.size - 1) as usize;
                let last_copy_idx = last_orig_seg_idx.min(last_sanitized_byte_idx);
                let sanitized_start_idx = collected_up_to - sanitized.offset as usize;
                let sanitized_end_idx = last_copy_idx - sanitized.offset as usize;

                for byte in &sanitized.bytes[sanitized_start_idx..=sanitized_end_idx] {
                    collected_bytes.insert(collected_up_to - orig.offset as usize, *byte);
                    collected_up_to += 1;
                }
                // All bytes collected
                if collected_up_to >= last_orig_seg_idx + 1 { break; }
            }
        }
        // When last byte of original segment is found, then add ResultSegment to result and move on
        result.push(ResultSegment {
            offset: orig.offset,
            bytes: collected_bytes,
        });
    }
    result
}

// [(5..7), (2..4), (3.5)] -> [(2..7)]
#[test]
fn sanitize_works() {
    let test: [Segment; 3] = [
        Segment { offset: 5, size: 2},
        Segment { offset: 2, size: 2},
        Segment { offset: 3, size: 2},
    ];

    let sanitized = sanitize(&test);

    assert_eq!(sanitized, vec![Segment { offset: 2, size: 5 }]);
}

#[test]
fn orig_from_sanitized_works() {
    let bytes: [u8; 7] = [0x1a, 0x2b, 0x36, 0x54, 0x3b, 0x1c, 0x3f];
    let segments: [Segment; 3] = [
        Segment { offset: 5, size: 2},
        Segment { offset: 2, size: 2},
        Segment { offset: 3, size: 2},
    ];

    let sanitized = sanitize(&segments);

    let sanitized_segments_data = extract_ranges_from_bytes(&bytes, &sanitized);
    let result_segments = extract_original_byte_ranges_from_sanitized(sanitized_segments_data, &segments);

    let original_segments_data = extract_ranges_from_bytes(&bytes, &segments);
    assert_eq!(result_segments, original_segments_data);
}