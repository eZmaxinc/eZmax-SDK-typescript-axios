# ObjectEzsigntemplateformfieldgroupApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplateformfieldgroupCreateObjectV1**](#ezsigntemplateformfieldgroupcreateobjectv1) | **POST** /1/object/ezsigntemplateformfieldgroup | Create a new Ezsigntemplateformfieldgroup|
|[**ezsigntemplateformfieldgroupDeleteObjectV1**](#ezsigntemplateformfieldgroupdeleteobjectv1) | **DELETE** /1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID} | Delete an existing Ezsigntemplateformfieldgroup|
|[**ezsigntemplateformfieldgroupEditObjectV1**](#ezsigntemplateformfieldgroupeditobjectv1) | **PUT** /1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID} | Edit an existing Ezsigntemplateformfieldgroup|
|[**ezsigntemplateformfieldgroupGetObjectV2**](#ezsigntemplateformfieldgroupgetobjectv2) | **GET** /2/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID} | Retrieve an existing Ezsigntemplateformfieldgroup|

# **ezsigntemplateformfieldgroupCreateObjectV1**
> EzsigntemplateformfieldgroupCreateObjectV1Response ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplateformfieldgroupApi,
    Configuration,
    EzsigntemplateformfieldgroupCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateformfieldgroupApi(configuration);

let ezsigntemplateformfieldgroupCreateObjectV1Request: EzsigntemplateformfieldgroupCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplateformfieldgroupCreateObjectV1(
    ezsigntemplateformfieldgroupCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateformfieldgroupCreateObjectV1Request** | **EzsigntemplateformfieldgroupCreateObjectV1Request**|  | |


### Return type

**EzsigntemplateformfieldgroupCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateformfieldgroupDeleteObjectV1**
> EzsigntemplateformfieldgroupDeleteObjectV1Response ezsigntemplateformfieldgroupDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplateformfieldgroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateformfieldgroupApi(configuration);

let pkiEzsigntemplateformfieldgroupID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateformfieldgroupDeleteObjectV1(
    pkiEzsigntemplateformfieldgroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateformfieldgroupDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateformfieldgroupEditObjectV1**
> EzsigntemplateformfieldgroupEditObjectV1Response ezsigntemplateformfieldgroupEditObjectV1(ezsigntemplateformfieldgroupEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplateformfieldgroupApi,
    Configuration,
    EzsigntemplateformfieldgroupEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateformfieldgroupApi(configuration);

let pkiEzsigntemplateformfieldgroupID: number; // (default to undefined)
let ezsigntemplateformfieldgroupEditObjectV1Request: EzsigntemplateformfieldgroupEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplateformfieldgroupEditObjectV1(
    pkiEzsigntemplateformfieldgroupID,
    ezsigntemplateformfieldgroupEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateformfieldgroupEditObjectV1Request** | **EzsigntemplateformfieldgroupEditObjectV1Request**|  | |
| **pkiEzsigntemplateformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateformfieldgroupEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateformfieldgroupGetObjectV2**
> EzsigntemplateformfieldgroupGetObjectV2Response ezsigntemplateformfieldgroupGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplateformfieldgroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateformfieldgroupApi(configuration);

let pkiEzsigntemplateformfieldgroupID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateformfieldgroupGetObjectV2(
    pkiEzsigntemplateformfieldgroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateformfieldgroupGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

