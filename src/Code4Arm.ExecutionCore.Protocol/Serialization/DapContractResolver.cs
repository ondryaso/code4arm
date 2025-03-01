﻿// DapContractResolver.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Serialization;

internal class DapContractResolver : DefaultContractResolver
{
    public DapContractResolver()
    {
        NamingStrategy = new CamelCaseNamingStrategy(true, false, true);
    }

    protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
    {
        var property = base.CreateProperty(member, memberSerialization);
        if (member.GetCustomAttributes<OptionalAttribute>(true).Any()
            || property.DeclaringType.Name.EndsWith("Capabilities")
           )
        {
            property.NullValueHandling = NullValueHandling.Ignore;
            property.DefaultValueHandling = DefaultValueHandling.Ignore;
        }

        return property;
    }
}
