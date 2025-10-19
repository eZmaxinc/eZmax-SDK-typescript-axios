# ObjectEzsigntemplatepackagesignermembershipApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatepackagesignermembershipCreateObjectV1**](#ezsigntemplatepackagesignermembershipcreateobjectv1) | **POST** /1/object/ezsigntemplatepackagesignermembership | Create a new Ezsigntemplatepackagesignermembership|
|[**ezsigntemplatepackagesignermembershipDeleteObjectV1**](#ezsigntemplatepackagesignermembershipdeleteobjectv1) | **DELETE** /1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID} | Delete an existing Ezsigntemplatepackagesignermembership|
|[**ezsigntemplatepackagesignermembershipGetObjectV2**](#ezsigntemplatepackagesignermembershipgetobjectv2) | **GET** /2/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID} | Retrieve an existing Ezsigntemplatepackagesignermembership|

# **ezsigntemplatepackagesignermembershipCreateObjectV1**
> EzsigntemplatepackagesignermembershipCreateObjectV1Response ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignermembershipApi,
    Configuration,
    EzsigntemplatepackagesignermembershipCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignermembershipApi(configuration);

let ezsigntemplatepackagesignermembershipCreateObjectV1Request: EzsigntemplatepackagesignermembershipCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagesignermembershipCreateObjectV1(
    ezsigntemplatepackagesignermembershipCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagesignermembershipCreateObjectV1Request** | **EzsigntemplatepackagesignermembershipCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatepackagesignermembershipCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepackagesignermembershipDeleteObjectV1**
> EzsigntemplatepackagesignermembershipDeleteObjectV1Response ezsigntemplatepackagesignermembershipDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignermembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignermembershipApi(configuration);

let pkiEzsigntemplatepackagesignermembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagesignermembershipDeleteObjectV1(
    pkiEzsigntemplatepackagesignermembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagesignermembershipID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignermembershipDeleteObjectV1Response**

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

# **ezsigntemplatepackagesignermembershipGetObjectV2**
> EzsigntemplatepackagesignermembershipGetObjectV2Response ezsigntemplatepackagesignermembershipGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignermembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignermembershipApi(configuration);

let pkiEzsigntemplatepackagesignermembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagesignermembershipGetObjectV2(
    pkiEzsigntemplatepackagesignermembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagesignermembershipID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignermembershipGetObjectV2Response**

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

