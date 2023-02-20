// menuSpec = http.Get("https://api.mastertime.io/v1/menu_spec/web-user")
let menuSpec = {
    "menu:::employee": {
        "require_resource_policy": [
            {
                "Resource": "res:::employee",
                "Action": [
                    "act:::employee:list",
                    "act:::employee:read",
                    "act:::employee:update",
                    "act:::employee:delete"
                ]
            },
            {
                "Resource": "res:::employee:biometric",
                "Action": [
                    "act:::employee:biometric:list",
                    "act:::employee:biometric:read",
                    "act:::employee:biometric:update",
                    "act:::employee:biometric:delete"
                ]
            }
        ]
    }
}

let isShowEmployeeMenu = authority.New(me, policy).IsValidMenu(menuSpec, "menu:::employee")

