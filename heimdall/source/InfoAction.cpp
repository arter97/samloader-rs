#include "ActionInterfaces.h"
#include "Interface.h"

int Heimdall::action_info() {
    Heimdall::Interface::PrintFullInfo();
    return 0;
}