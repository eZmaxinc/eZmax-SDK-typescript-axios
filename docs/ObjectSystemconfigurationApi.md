# ObjectSystemconfigurationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**systemconfigurationEditObjectV1**](#systemconfigurationeditobjectv1) | **PUT** /1/object/systemconfiguration/{pkiSystemconfigurationID} | Edit an existing Systemconfiguration|
|[**systemconfigurationGetObjectV2**](#systemconfigurationgetobjectv2) | **GET** /2/object/systemconfiguration/{pkiSystemconfigurationID} | Retrieve an existing Systemconfiguration|

# **systemconfigurationEditObjectV1**
> SystemconfigurationEditObjectV1Response systemconfigurationEditObjectV1(systemconfigurationEditObjectV1Request)



### Example

```typescript
import {
    ObjectSystemconfigurationApi,
    Configuration,
    SystemconfigurationEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSystemconfigurationApi(configuration);

let pkiSystemconfigurationID: number; //The unique ID of the Systemconfiguration (default to undefined)
let systemconfigurationEditObjectV1Request: SystemconfigurationEditObjectV1Request; //

const { status, data } = await apiInstance.systemconfigurationEditObjectV1(
    pkiSystemconfigurationID,
    systemconfigurationEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **systemconfigurationEditObjectV1Request** | **SystemconfigurationEditObjectV1Request**|  | |
| **pkiSystemconfigurationID** | [**number**] | The unique ID of the Systemconfiguration | defaults to undefined|


### Return type

**SystemconfigurationEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **systemconfigurationGetObjectV2**
> SystemconfigurationGetObjectV2Response systemconfigurationGetObjectV2()



### Example

```typescript
import {
    ObjectSystemconfigurationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSystemconfigurationApi(configuration);

let pkiSystemconfigurationID: number; //The unique ID of the Systemconfiguration (default to undefined)

const { status, data } = await apiInstance.systemconfigurationGetObjectV2(
    pkiSystemconfigurationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSystemconfigurationID** | [**number**] | The unique ID of the Systemconfiguration | defaults to undefined|


### Return type

**SystemconfigurationGetObjectV2Response**

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

