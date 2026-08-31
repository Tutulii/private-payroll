use dep::bignum::RuntimeBigNum;
use dep::bignum::params::BigNumParams;
use dep::bignum::runtime_bignum::evaluate_quadratic_expression;
use crate::stark_poseidon_constants::STARK_POSEIDON_ROUND_CONSTANT_LIMBS;

pub global STARK_FIELD_PARAMS: BigNumParams<3, 252> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x1, 0x11000000000000000000, 0x800],
    double_modulus: [
        0x1000000000000000000000000000002,
        0x1000000000021ffffffffffffffffff,
        0xfff,
    ],
    redc_param: [
        0xffffffeccf000000000028c81fffbf,
        0xfffffffffbc000000000000907ffff,
        0x1ffff,
    ],
};

pub type StarkFelt = RuntimeBigNum<3, 252>;

pub fn from_limbs(limbs: [u128; 3]) -> StarkFelt {
    RuntimeBigNum::from_array(STARK_FIELD_PARAMS, limbs)
}

fn constant(index: u32) -> StarkFelt {
    from_limbs(STARK_POSEIDON_ROUND_CONSTANT_LIMBS[index])
}

pub fn from_u128(value: u128) -> StarkFelt {
    from_limbs([value, 0, 0])
}

fn assert_linear_zero<let N: u32>(terms: [StarkFelt; N], negative: [bool; N]) {
    let zero = StarkFelt::zero(STARK_FIELD_PARAMS);
    evaluate_quadratic_expression(
        STARK_FIELD_PARAMS,
        [[zero]],
        [[false]],
        [[zero]],
        [[false]],
        terms,
        negative,
    );
}

fn add(left: StarkFelt, right: StarkFelt) -> StarkFelt {
    // Safety: this reduced witness is fully constrained by the linear relation.
    let result = left.__add(right);
    assert_linear_zero([left, right, result], [false, false, true]);
    result
}

fn cube_with_constant(value: StarkFelt, round_constant: StarkFelt) -> StarkFelt {
    // Safety: both reduced witnesses are constrained by the quadratic relations.
    let shifted = value.__add(round_constant);
    let square = shifted.__sqr();
    let cube = square.__mul(shifted);
    evaluate_quadratic_expression(
        STARK_FIELD_PARAMS,
        [[value, round_constant]],
        [[false, false]],
        [[value, round_constant]],
        [[false, false]],
        [square],
        [true],
    );
    evaluate_quadratic_expression(
        STARK_FIELD_PARAMS,
        [[square]],
        [[false]],
        [[value, round_constant]],
        [[false, false]],
        [cube],
        [true],
    );
    cube
}

fn full_mix(left: StarkFelt, middle: StarkFelt, right: StarkFelt) -> [StarkFelt; 3] {
    // Safety: each reduced witness is constrained by its MDS linear relation.
    let output_0 = left.__add(left).__add(left).__add(middle).__add(right);
    let output_1 = left.__sub(middle).__add(right);
    let output_2 = left.__add(middle).__sub(right).__sub(right);
    assert_linear_zero(
        [left, left, left, middle, right, output_0],
        [false, false, false, false, false, true],
    );
    assert_linear_zero(
        [left, middle, right, output_1],
        [false, true, false, true],
    );
    assert_linear_zero(
        [left, middle, right, right, output_2],
        [false, false, true, true, true],
    );
    [output_0, output_1, output_2]
}

fn partial_mix(
    left: StarkFelt,
    middle: StarkFelt,
    right_cube: StarkFelt,
    left_constant: StarkFelt,
    middle_constant: StarkFelt,
) -> [StarkFelt; 3] {
    // Safety: each reduced witness is constrained by its partial-round relation.
    let output_0 =
        left.__add(left)
            .__add(left)
            .__add(left_constant)
            .__add(left_constant)
            .__add(left_constant)
            .__add(middle)
            .__add(middle_constant)
            .__add(right_cube);
    let output_1 =
        left.__add(left_constant)
            .__sub(middle)
            .__sub(middle_constant)
            .__add(right_cube);
    let output_2 =
        left.__add(left_constant)
            .__add(middle)
            .__add(middle_constant)
            .__sub(right_cube)
            .__sub(right_cube);
    assert_linear_zero(
        [
            left, left, left, left_constant, left_constant, left_constant,
            middle, middle_constant, right_cube, output_0,
        ],
        [false, false, false, false, false, false, false, false, false, true],
    );
    assert_linear_zero(
        [left, left_constant, middle, middle_constant, right_cube, output_1],
        [false, false, true, true, false, true],
    );
    assert_linear_zero(
        [left, left_constant, middle, middle_constant, right_cube, right_cube, output_2],
        [false, false, false, false, true, true, true],
    );
    [output_0, output_1, output_2]
}

pub fn permutation(mut state: [StarkFelt; 3]) -> [StarkFelt; 3] {
    for round in 0..91 {
        let offset = round * 3;
        let constants = [constant(offset), constant(offset + 1), constant(offset + 2)];
        if (round < 4) | (round >= 87) {
            state = full_mix(
                cube_with_constant(state[0], constants[0]),
                cube_with_constant(state[1], constants[1]),
                cube_with_constant(state[2], constants[2]),
            );
        } else {
            state = partial_mix(
                state[0],
                state[1],
                cube_with_constant(state[2], constants[2]),
                constants[0],
                constants[1],
            );
        }
    }
    state
}

fn assert_canonical<let N: u32>(values: [StarkFelt; N]) {
    for index in 0..N {
        values[index].validate_in_field();
    }
}

pub fn hash_many_5(values: [StarkFelt; 5]) -> StarkFelt {
    assert_canonical(values);
    let zero = StarkFelt::zero(STARK_FIELD_PARAMS);
    let mut state = permutation([values[0], values[1], zero]);
    state = permutation([add(state[0], values[2]), add(state[1], values[3]), state[2]]);
    state = permutation([
        add(state[0], values[4]),
        add(state[1], StarkFelt::one(STARK_FIELD_PARAMS)),
        state[2],
    ]);
    state[0]
}

pub fn hash_many_6(values: [StarkFelt; 6]) -> StarkFelt {
    assert_canonical(values);
    let zero = StarkFelt::zero(STARK_FIELD_PARAMS);
    let mut state = permutation([values[0], values[1], zero]);
    state = permutation([add(state[0], values[2]), add(state[1], values[3]), state[2]]);
    state = permutation([add(state[0], values[4]), add(state[1], values[5]), state[2]]);
    state = permutation([
        add(state[0], StarkFelt::one(STARK_FIELD_PARAMS)),
        state[1],
        state[2],
    ]);
    state[0]
}

#[test]
fn matches_official_cairo_note_id_vector() {
    let actual = hash_many_5([
        from_limbs([0x4e4f54455f49445f5441473a5631, 0, 0]),
        from_u128(0xdef),
        from_u128(0x1234),
        from_u128(5),
        StarkFelt::zero(STARK_FIELD_PARAMS),
    ]);
    let expected = from_limbs([
        0x48f24efcabd5a64ac941e9a05777e8,
        0x98ad0b0b4b1881a77f962eb0650de7,
        0x6b0,
    ]);
    assert(actual == expected);
}

#[test]
fn matches_official_cairo_encrypted_amount_vector() {
    let actual = hash_many_6([
        from_limbs([0x435f414d4f554e545f5441473a5631, 0x454e, 0]),
        from_u128(0xdef),
        from_u128(0x1234),
        from_u128(5),
        StarkFelt::zero(STARK_FIELD_PARAMS),
        from_u128(0x5678),
    ]);
    let expected = from_limbs([
        0x60f260ec796ecdd862d35616ea6b40,
        0x52b70967da5d0a5042bc96f72d41e8,
        0x39b,
    ]);
    assert(actual == expected);
}
