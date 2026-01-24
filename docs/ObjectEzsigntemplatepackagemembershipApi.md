# ObjectEzsigntemplatepackagemembershipApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatepackagemembershipCreateObjectV1**](#ezsigntemplatepackagemembershipcreateobjectv1) | **POST** /1/object/ezsigntemplatepackagemembership | Create a new Ezsigntemplatepackagemembership|
|[**ezsigntemplatepackagemembershipDeleteObjectV1**](#ezsigntemplatepackagemembershipdeleteobjectv1) | **DELETE** /1/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID} | Delete an existing Ezsigntemplatepackagemembership|
|[**ezsigntemplatepackagemembershipGetObjectV2**](#ezsigntemplatepackagemembershipgetobjectv2) | **GET** /2/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID} | Retrieve an existing Ezsigntemplatepackagemembership|

# **ezsigntemplatepackagemembershipCreateObjectV1**
> EzsigntemplatepackagemembershipCreateObjectV1Response ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepackagemembershipApi,
    Configuration,
    EzsigntemplatepackagemembershipCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagemembershipApi(configuration);

let ezsigntemplatepackagemembershipCreateObjectV1Request: EzsigntemplatepackagemembershipCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagemembershipCreateObjectV1(
    ezsigntemplatepackagemembershipCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagemembershipCreateObjectV1Request** | **EzsigntemplatepackagemembershipCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatepackagemembershipCreateObjectV1Response**

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

# **ezsigntemplatepackagemembershipDeleteObjectV1**
> EzsigntemplatepackagemembershipDeleteObjectV1Response ezsigntemplatepackagemembershipDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagemembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagemembershipApi(configuration);

let pkiEzsigntemplatepackagemembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagemembershipDeleteObjectV1(
    pkiEzsigntemplatepackagemembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagemembershipID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagemembershipDeleteObjectV1Response**

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

# **ezsigntemplatepackagemembershipGetObjectV2**
> EzsigntemplatepackagemembershipGetObjectV2Response ezsigntemplatepackagemembershipGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagemembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagemembershipApi(configuration);

let pkiEzsigntemplatepackagemembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagemembershipGetObjectV2(
    pkiEzsigntemplatepackagemembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagemembershipID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagemembershipGetObjectV2Response**

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

