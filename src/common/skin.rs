use once_cell::sync::Lazy;
use rgb::ComponentBytes;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SkinModel {
    Classic,
    Slim,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SkinPart {
    Head,
    ArmLeft,
    ArmRight,
    Body,
    LegLeft,
    LegRight,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SkinLayer {
    Bottom,
    Top,
    #[allow(dead_code)]
    Both,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum SkinFace {
    Top,
    Bottom,
    Right,
    Front,
    Left,
    Back,
}

pub struct SkinSection<'a>(pub &'a SkinPart, pub SkinLayer);

static ALEX_PNG: &[u8] = include_bytes!("../../resources/default/skin/alex_slim.png");
static STEVE_PNG: &[u8] = include_bytes!("../../resources/default/skin/steve_classic.png");

pub static ALEX_SKIN: Lazy<Vec<u8>> = Lazy::new(|| {
    lodepng::decode32(ALEX_PNG).unwrap().buffer.as_bytes().to_vec()
});

pub static STEVE_SKIN: Lazy<Vec<u8>> = Lazy::new(|| {
    lodepng::decode32(STEVE_PNG).unwrap().buffer.as_bytes().to_vec()
});
