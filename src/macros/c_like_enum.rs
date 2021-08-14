#[macro_export]
macro_rules! c_like_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $enum_name:ident($field_type:ty) {
            $($field_name:ident = $field_value:literal,)+
        }
    ) => {
        $(#[$meta])*
        $vis enum $enum_name {
            $(
                $field_name,
            )+
            Unknown($field_type),
        }

        impl From<$field_type> for $enum_name {
            fn from(value: $field_type) -> Self {
                match value {
                    $(
                        $field_value => $enum_name::$field_name,
                    )+
                    unknown => $enum_name::Unknown(unknown),
                }
            }
        }

        impl From<$enum_name> for $field_type {
            fn from(value: $enum_name) -> $field_type {
                match value {
                    $(
                        $enum_name::$field_name => $field_value,
                    )+
                    $enum_name::Unknown(unknown) => unknown,
                }
            }
        }
    };
}
