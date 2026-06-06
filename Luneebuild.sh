# Vérification
cargo check -p vuc-core --target x86_64-unknown-uefi

# Compilation en mode debug
cargo build -p vuc-core --target x86_64-unknown-uefi

# Compilation optimisée (Production)
cargo build -p vuc-core --target x86_64-unknown-uefi --release
