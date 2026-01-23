# ObjectNotificationtestApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**notificationtestGetElementsV2**](#notificationtestgetelementsv2) | **GET** /2/object/notificationtest/{pkiNotificationtestID}/getElements | Retrieve an existing Notificationtest\&#39;s Elements|

# **notificationtestGetElementsV2**
> NotificationtestGetElementsV2Response notificationtestGetElementsV2()



### Example

```typescript
import {
    ObjectNotificationtestApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotificationtestApi(configuration);

let pkiNotificationtestID: number; // (default to undefined)

const { status, data } = await apiInstance.notificationtestGetElementsV2(
    pkiNotificationtestID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotificationtestID** | [**number**] |  | defaults to undefined|


### Return type

**NotificationtestGetElementsV2Response**

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

