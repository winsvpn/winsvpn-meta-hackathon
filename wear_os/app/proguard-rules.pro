# Wear R8 keep contract.
#
# Android instantiates the launcher activity by class name. Keep that name and
# its public constructor. Do not keep the rest of the implementation surface.
# These rules are a static contract. They do not prove a successful R8 run.

-keep class org.winsvpn.app.wear.MainActivity {
    <init>();
}

