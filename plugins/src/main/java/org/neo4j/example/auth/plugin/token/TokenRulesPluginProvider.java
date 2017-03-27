/**
 * Copyright (c) 2002-2016 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.example.auth.plugin.token;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import org.neo4j.server.security.enterprise.auth.plugin.spi.PluginTokenRules;
import org.neo4j.server.security.enterprise.auth.plugin.spi.TokenRuleProvider;

public class TokenRulesPluginProvider implements TokenRuleProvider
{
    private static final Map<String,List<String>> blacklist = new HashMap<>();
    private static final String KEY_VALUE_SEP = "=";
    private static final String TOKEN_SEP = ",";

    @Override
    public String name()
    {
        return "TokenRulesPluginProvider";
    }

    @Override
    public void init( AuthProviderOperations authProviderOperations ) throws Throwable
    {
        Path neo4jHome = authProviderOperations.neo4jHome();
        Path confPath = neo4jHome.resolve( "conf" ).resolve( "tokenrules.conf" );
        parseRules( confPath );
    }

    private void parseRules( Path rulesPath ) throws IOException
    {
        List<String> lines = Files.readAllLines( rulesPath ).stream()
                .filter( line -> line != null && !line.trim().isEmpty() ).collect( Collectors.toList() );
        for (String line : lines )
        {
            String[] parts = line.split( KEY_VALUE_SEP, 2 );
            if ( parts.length != 2 )
            {
                throw new RuntimeException( "Bad formatting in config file" );
            }
            String[] deny = parts[1].split( TOKEN_SEP );
            blacklist.put( parts[0].trim(), Arrays.asList( deny ) );
        }
    }

    @Override
    public PluginTokenRules getTokenRules( Collection<String> roles )
    {
        Set<String> blackListed = new HashSet<>();
        for ( String role : roles )
        {
            if ( blacklist.containsKey( role ) )
            {
                blackListed.addAll( blacklist.get( role ) );
            }
        }

        return new PluginTokenRules()
        {
            public boolean allowsPropertyRead( String name )
            {
                return !blackListed.contains( name );
            }
        };
    }
}
