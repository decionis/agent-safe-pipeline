#!/usr/bin/env node

import { CommerceGateClient } from "./CommerceGateClient.js";
import { CommerceGateConfiguration } from "./Configuration.js";
import { createMcpHandler, CommerceGateStdioServer } from "./Server.js";
import { CommerceGateTools } from "./Tools.js";

const configuration = new CommerceGateConfiguration();
const client = new CommerceGateClient(configuration);
const tools = new CommerceGateTools(configuration, client).build();

await CommerceGateStdioServer.run(createMcpHandler(tools));
