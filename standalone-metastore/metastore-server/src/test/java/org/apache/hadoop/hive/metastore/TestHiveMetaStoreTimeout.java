/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hive.metastore;

import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.annotation.MetastoreCheckinTest;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.client.builder.DatabaseBuilder;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf.ConfVars;
import org.apache.thrift.transport.TTransportException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Test long running request timeout functionality in MetaStore Server
 * HMSHandler.create_database() is used to simulate a long running method.
 */
@Category(MetastoreCheckinTest.class)
public class TestHiveMetaStoreTimeout {
  protected static HiveMetaStoreClient client;
  protected static Configuration conf;
  protected static Warehouse warehouse;
  protected static int port;

  @BeforeClass
  public static void startMetaStoreServer() throws Exception {
    HMSHandler.testTimeoutEnabled = true;
    conf = MetastoreConf.newMetastoreConf();
    MetastoreConf.setClass(conf, ConfVars.EXPRESSION_PROXY_CLASS,
        MockPartitionExpressionForMetastore.class, PartitionExpressionProxy.class);
    MetastoreConf.setTimeVar(conf, ConfVars.CLIENT_SOCKET_TIMEOUT, 1000,
        TimeUnit.MILLISECONDS);
    MetaStoreTestUtils.setConfForStandloneMode(conf);
    warehouse = new Warehouse(conf);
    port = MetaStoreTestUtils.startMetaStoreWithRetry(conf);
    MetastoreConf.setVar(conf, ConfVars.THRIFT_URIS, "thrift://localhost:" + port);
    MetastoreConf.setBoolVar(conf, ConfVars.EXECUTE_SET_UGI, false);
  }

  @AfterClass
  public static void tearDown() {
    HMSHandler.testTimeoutEnabled = false;
  }

  @Before
  public void setup() throws MetaException {
    client = new HiveMetaStoreClient(conf);
  }

  @After
  public void cleanup() {
    client.close();
    client = null;
  }

  @Test
  public void testNoTimeout() throws Exception {
    HMSHandler.testTimeoutValue = 250;

    String dbName = "db";
    client.dropDatabase(dbName, true, true);

    new DatabaseBuilder()
        .setName(dbName)
        .create(client, conf);

    client.dropDatabase(dbName, true, true);
  }

  @Test
  public void testTimeout() throws Exception {
    HMSHandler.testTimeoutValue = 2 * 1000;

    String dbName = "db";
    client.dropDatabase(dbName, true, true);

    Database db = new DatabaseBuilder()
        .setName(dbName)
        .build(conf);
    try {
      client.createDatabase(db);
      Assert.fail("should throw timeout exception.");
    } catch (TTransportException e) {
      Assert.assertTrue("unexpected Exception", e.getMessage().contains("Read timed out"));
    }

    // restore
    HMSHandler.testTimeoutValue = 1;
  }

  @Test
  public void testResetTimeout() throws Exception {
    HMSHandler.testTimeoutValue = 250;
    String dbName = "db";

    // no timeout before reset
    client.dropDatabase(dbName, true, true);
    Database db = new DatabaseBuilder()
        .setName(dbName)
        .build(conf);
    try {
      client.createDatabase(db);
    } catch (Exception e) {
      Assert.fail("should not throw timeout exception: " + e.getMessage());
    }
    client.dropDatabase(dbName, true, true);

    // reset
    HMSHandler.testTimeoutValue = 2000;
    client.setMetaConf(ConfVars.CLIENT_SOCKET_TIMEOUT.getVarname(), "1s");

    // timeout after reset
    try {
      client.createDatabase(db);
      Assert.fail("should throw timeout exception.");
    } catch (TTransportException e) {
      Assert.assertTrue("unexpected Exception", e.getMessage().contains("Read timed out"));
    }
  }

  @Test
  public void testConnectionTimeout() throws Exception {
    Configuration newConf = new Configuration(conf);
    MetastoreConf.setTimeVar(newConf, ConfVars.CLIENT_CONNECTION_TIMEOUT, 1000,
            TimeUnit.MILLISECONDS);
    // fake host to mock connection time out
    MetastoreConf.setVar(newConf, ConfVars.THRIFT_URIS, "thrift://1.1.1.1:" + port);
    MetastoreConf.setLongVar(newConf, ConfVars.THRIFT_CONNECTION_RETRIES, 1);

    Future<Void> future = Executors.newSingleThreadExecutor().submit(() -> {
      try(HiveMetaStoreClient c = new HiveMetaStoreClient(newConf)) {
        Assert.fail("should throw connection timeout exception.");
      } catch (MetaException e) {
        Assert.assertTrue("unexpected Exception", e.getMessage().contains("connect timed out"));
      }
      return null;
    });
    future.get(5, TimeUnit.SECONDS);
  }
}
