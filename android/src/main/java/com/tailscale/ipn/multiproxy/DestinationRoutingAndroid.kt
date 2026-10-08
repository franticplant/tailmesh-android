// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.net.LinkProperties

/**
 * Android glue for [DestinationRouting]: turns a network's [LinkProperties] into the pure
 * [LocalRoute] list the selection reads. Kept separate so [DestinationRouting] itself stays free of
 * Android types and host-testable without Robolectric.
 *
 * Not yet called by production code - see [DestinationRouting]'s note.
 */
fun LinkProperties.toLocalRoutes(networkKey: String): List<LocalRoute> =
    routes.mapNotNull { route ->
      val dest = route.destination ?: return@mapNotNull null
      val address = dest.address ?: return@mapNotNull null
      LocalRoute(
          networkKey = networkKey,
          interfaceName = interfaceName,
          destinationCidr = "${address.hostAddress}/${dest.prefixLength}",
          isDefaultRoute = route.isDefaultRoute,
          hasGateway = route.gateway != null,
      )
    }
