# ObjectEzsignformfieldgroupApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignformfieldgroupCreateObjectV1**](#ezsignformfieldgroupcreateobjectv1) | **POST** /1/object/ezsignformfieldgroup | Create a new Ezsignformfieldgroup|
|[**ezsignformfieldgroupDeleteObjectV1**](#ezsignformfieldgroupdeleteobjectv1) | **DELETE** /1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID} | Delete an existing Ezsignformfieldgroup|
|[**ezsignformfieldgroupEditObjectV1**](#ezsignformfieldgroupeditobjectv1) | **PUT** /1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID} | Edit an existing Ezsignformfieldgroup|
|[**ezsignformfieldgroupGetObjectV2**](#ezsignformfieldgroupgetobjectv2) | **GET** /2/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID} | Retrieve an existing Ezsignformfieldgroup|

# **ezsignformfieldgroupCreateObjectV1**
> EzsignformfieldgroupCreateObjectV1Response ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignformfieldgroupApi,
    Configuration,
    EzsignformfieldgroupCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignformfieldgroupApi(configuration);

let ezsignformfieldgroupCreateObjectV1Request: EzsignformfieldgroupCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignformfieldgroupCreateObjectV1(
    ezsignformfieldgroupCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignformfieldgroupCreateObjectV1Request** | **EzsignformfieldgroupCreateObjectV1Request**|  | |


### Return type

**EzsignformfieldgroupCreateObjectV1Response**

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

# **ezsignformfieldgroupDeleteObjectV1**
> EzsignformfieldgroupDeleteObjectV1Response ezsignformfieldgroupDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignformfieldgroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignformfieldgroupApi(configuration);

let pkiEzsignformfieldgroupID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignformfieldgroupDeleteObjectV1(
    pkiEzsignformfieldgroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignformfieldgroupDeleteObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignformfieldgroupEditObjectV1**
> EzsignformfieldgroupEditObjectV1Response ezsignformfieldgroupEditObjectV1(ezsignformfieldgroupEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignformfieldgroupApi,
    Configuration,
    EzsignformfieldgroupEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignformfieldgroupApi(configuration);

let pkiEzsignformfieldgroupID: number; // (default to undefined)
let ezsignformfieldgroupEditObjectV1Request: EzsignformfieldgroupEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignformfieldgroupEditObjectV1(
    pkiEzsignformfieldgroupID,
    ezsignformfieldgroupEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignformfieldgroupEditObjectV1Request** | **EzsignformfieldgroupEditObjectV1Request**|  | |
| **pkiEzsignformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignformfieldgroupEditObjectV1Response**

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

# **ezsignformfieldgroupGetObjectV2**
> EzsignformfieldgroupGetObjectV2Response ezsignformfieldgroupGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignformfieldgroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignformfieldgroupApi(configuration);

let pkiEzsignformfieldgroupID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignformfieldgroupGetObjectV2(
    pkiEzsignformfieldgroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignformfieldgroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignformfieldgroupGetObjectV2Response**

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

