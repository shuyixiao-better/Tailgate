# Pin the SSH test image; production Tailgate requires no container runtime.
FROM lscr.io/linuxserver/openssh-server@sha256:946fa26105e0ec212fdf821b9ddc59aab65f2c2d07c02b25ff0f5001fc332ff0

# Match the GNU find/grep/df/ps utilities shipped by Ubuntu targets. This image uses
# Alpine and deliberately has no systemd: its unavailable-service path is tested.
RUN apk add --no-cache coreutils findutils grep procps sudo
COPY integration/setup-fixtures.sh /custom-cont-init.d/99-tailgate-fixtures
RUN chmod 0755 /custom-cont-init.d/99-tailgate-fixtures
