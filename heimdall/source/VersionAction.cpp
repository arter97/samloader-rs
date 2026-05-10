#include "ActionInterfaces.h"
#include "Interface.h"

int Heimdall::action_version() {
    Heimdall::Interface::PrintVersion();
    return 0;
}