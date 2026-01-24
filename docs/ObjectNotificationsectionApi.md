# ObjectNotificationsectionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**notificationsectionGetNotificationtestsV1**](#notificationsectiongetnotificationtestsv1) | **GET** /1/object/notificationsection/{pkiNotificationsectionID}/getNotificationtests | Retrieve an existing Notificationsection\&#39;s Notificationtests|

# **notificationsectionGetNotificationtestsV1**
> NotificationsectionGetNotificationtestsV1Response notificationsectionGetNotificationtestsV1()



### Example

```typescript
import {
    ObjectNotificationsectionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotificationsectionApi(configuration);

let pkiNotificationsectionID: number; // (default to undefined)
let bShowHidden: boolean; //Whether or not to return the hidden Notificationtests (default to undefined)

const { status, data } = await apiInstance.notificationsectionGetNotificationtestsV1(
    pkiNotificationsectionID,
    bShowHidden
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotificationsectionID** | [**number**] |  | defaults to undefined|
| **bShowHidden** | [**boolean**] | Whether or not to return the hidden Notificationtests | defaults to undefined|


### Return type

**NotificationsectionGetNotificationtestsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

