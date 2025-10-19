# ObjectEzsignannotationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignannotationCreateObjectV1**](#ezsignannotationcreateobjectv1) | **POST** /1/object/ezsignannotation | Create a new Ezsignannotation|
|[**ezsignannotationDeleteObjectV1**](#ezsignannotationdeleteobjectv1) | **DELETE** /1/object/ezsignannotation/{pkiEzsignannotationID} | Delete an existing Ezsignannotation|
|[**ezsignannotationEditObjectV1**](#ezsignannotationeditobjectv1) | **PUT** /1/object/ezsignannotation/{pkiEzsignannotationID} | Edit an existing Ezsignannotation|
|[**ezsignannotationGetObjectV2**](#ezsignannotationgetobjectv2) | **GET** /2/object/ezsignannotation/{pkiEzsignannotationID} | Retrieve an existing Ezsignannotation|

# **ezsignannotationCreateObjectV1**
> EzsignannotationCreateObjectV1Response ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignannotationApi,
    Configuration,
    EzsignannotationCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignannotationApi(configuration);

let ezsignannotationCreateObjectV1Request: EzsignannotationCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignannotationCreateObjectV1(
    ezsignannotationCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignannotationCreateObjectV1Request** | **EzsignannotationCreateObjectV1Request**|  | |


### Return type

**EzsignannotationCreateObjectV1Response**

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

# **ezsignannotationDeleteObjectV1**
> EzsignannotationDeleteObjectV1Response ezsignannotationDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignannotationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignannotationApi(configuration);

let pkiEzsignannotationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignannotationDeleteObjectV1(
    pkiEzsignannotationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignannotationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignannotationDeleteObjectV1Response**

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

# **ezsignannotationEditObjectV1**
> EzsignannotationEditObjectV1Response ezsignannotationEditObjectV1(ezsignannotationEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignannotationApi,
    Configuration,
    EzsignannotationEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignannotationApi(configuration);

let pkiEzsignannotationID: number; // (default to undefined)
let ezsignannotationEditObjectV1Request: EzsignannotationEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignannotationEditObjectV1(
    pkiEzsignannotationID,
    ezsignannotationEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignannotationEditObjectV1Request** | **EzsignannotationEditObjectV1Request**|  | |
| **pkiEzsignannotationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignannotationEditObjectV1Response**

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

# **ezsignannotationGetObjectV2**
> EzsignannotationGetObjectV2Response ezsignannotationGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignannotationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignannotationApi(configuration);

let pkiEzsignannotationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignannotationGetObjectV2(
    pkiEzsignannotationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignannotationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignannotationGetObjectV2Response**

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

