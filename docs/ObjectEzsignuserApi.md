# ObjectEzsignuserApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignuserEditObjectV1**](#ezsignusereditobjectv1) | **PUT** /1/object/ezsignuser/{pkiEzsignuserID} | Edit an existing Ezsignuser|
|[**ezsignuserGetObjectV2**](#ezsignusergetobjectv2) | **GET** /2/object/ezsignuser/{pkiEzsignuserID} | Retrieve an existing Ezsignuser|

# **ezsignuserEditObjectV1**
> EzsignuserEditObjectV1Response ezsignuserEditObjectV1(ezsignuserEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignuserApi,
    Configuration,
    EzsignuserEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignuserApi(configuration);

let pkiEzsignuserID: number; //The unique ID of the Ezsignuser (default to undefined)
let ezsignuserEditObjectV1Request: EzsignuserEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignuserEditObjectV1(
    pkiEzsignuserID,
    ezsignuserEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignuserEditObjectV1Request** | **EzsignuserEditObjectV1Request**|  | |
| **pkiEzsignuserID** | [**number**] | The unique ID of the Ezsignuser | defaults to undefined|


### Return type

**EzsignuserEditObjectV1Response**

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

# **ezsignuserGetObjectV2**
> EzsignuserGetObjectV2Response ezsignuserGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignuserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignuserApi(configuration);

let pkiEzsignuserID: number; //The unique ID of the Ezsignuser (default to undefined)

const { status, data } = await apiInstance.ezsignuserGetObjectV2(
    pkiEzsignuserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignuserID** | [**number**] | The unique ID of the Ezsignuser | defaults to undefined|


### Return type

**EzsignuserGetObjectV2Response**

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

