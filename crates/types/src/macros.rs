// Declaration macros for the generated modules (hand-written). They keep the generated files short: every string
// enum of the OpenAPI document becomes one `string_enum!` or `open_enum!` invocation.

/// A closed set of string values: a Rust enum whose variants serialize as the listed strings.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident = $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ::serde::Serialize, ::serde::Deserialize,
        )]
        $vis enum $name {
            $($(#[$variant_meta])* #[serde(rename = $value)] $variant,)+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The JSON string of this value.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $value,)+
                }
            }

            /// The value whose JSON string is `value`.
            #[allow(clippy::should_implement_trait)]
            pub fn from_str(value: &str) -> ::core::option::Option<Self> {
                match value {
                    $($value => ::core::option::Option::Some($name::$variant),)+
                    _ => ::core::option::Option::None,
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::core::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

/// An open set of string values (TypeScript's `'a' | 'b' | (string & {})`): any string, with the known values as
/// associated constants.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($(#[$const_meta:meta])* $constant:ident = $value:literal),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default, ::serde::Serialize, ::serde::Deserialize,
        )]
        #[serde(transparent)]
        $vis struct $name(pub ::std::string::String);

        impl $name {
            $($(#[$const_meta])* pub const $constant: &'static str = $value;)*

            /// The values the TypeScript declaration lists; others are allowed.
            pub const KNOWN: &'static [&'static str] = &[$($value),*];

            /// The string value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether the value is one of [`Self::KNOWN`].
            pub fn is_known(&self) -> bool {
                Self::KNOWN.contains(&self.0.as_str())
            }
        }

        impl ::core::convert::From<&str> for $name {
            fn from(value: &str) -> Self {
                $name(value.into())
            }
        }

        impl ::core::convert::From<::std::string::String> for $name {
            fn from(value: ::std::string::String) -> Self {
                $name(value)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::core::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl ::core::cmp::PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl ::core::cmp::PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }
    };
}
