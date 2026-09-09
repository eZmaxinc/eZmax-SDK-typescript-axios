# ObjectEzsigntemplateannotationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplateannotationCreateObjectV1**](#ezsigntemplateannotationcreateobjectv1) | **POST** /1/object/ezsigntemplateannotation | Create a new Ezsigntemplateannotation|
|[**ezsigntemplateannotationDeleteObjectV1**](#ezsigntemplateannotationdeleteobjectv1) | **DELETE** /1/object/ezsigntemplateannotation/{pkiEzsigntemplateannotationID} | Delete an existing Ezsigntemplateannotation|
|[**ezsigntemplateannotationEditObjectV1**](#ezsigntemplateannotationeditobjectv1) | **PUT** /1/object/ezsigntemplateannotation/{pkiEzsigntemplateannotationID} | Edit an existing Ezsigntemplateannotation|
|[**ezsigntemplateannotationGetObjectV2**](#ezsigntemplateannotationgetobjectv2) | **GET** /2/object/ezsigntemplateannotation/{pkiEzsigntemplateannotationID} | Retrieve an existing Ezsigntemplateannotation|

# **ezsigntemplateannotationCreateObjectV1**
> EzsigntemplateannotationCreateObjectV1Response ezsigntemplateannotationCreateObjectV1(ezsigntemplateannotationCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplateannotationApi,
    Configuration,
    EzsigntemplateannotationCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateannotationApi(configuration);

let ezsigntemplateannotationCreateObjectV1Request: EzsigntemplateannotationCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplateannotationCreateObjectV1(
    ezsigntemplateannotationCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateannotationCreateObjectV1Request** | **EzsigntemplateannotationCreateObjectV1Request**|  | |


### Return type

**EzsigntemplateannotationCreateObjectV1Response**

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

# **ezsigntemplateannotationDeleteObjectV1**
> EzsigntemplateannotationDeleteObjectV1Response ezsigntemplateannotationDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplateannotationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateannotationApi(configuration);

let pkiEzsigntemplateannotationID: number; //The unique ID of the Ezsigntemplateannotation (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateannotationDeleteObjectV1(
    pkiEzsigntemplateannotationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateannotationID** | [**number**] | The unique ID of the Ezsigntemplateannotation | defaults to undefined|


### Return type

**EzsigntemplateannotationDeleteObjectV1Response**

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

# **ezsigntemplateannotationEditObjectV1**
> EzsigntemplateannotationEditObjectV1Response ezsigntemplateannotationEditObjectV1(ezsigntemplateannotationEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplateannotationApi,
    Configuration,
    EzsigntemplateannotationEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateannotationApi(configuration);

let pkiEzsigntemplateannotationID: number; //The unique ID of the Ezsigntemplateannotation (default to undefined)
let ezsigntemplateannotationEditObjectV1Request: EzsigntemplateannotationEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplateannotationEditObjectV1(
    pkiEzsigntemplateannotationID,
    ezsigntemplateannotationEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateannotationEditObjectV1Request** | **EzsigntemplateannotationEditObjectV1Request**|  | |
| **pkiEzsigntemplateannotationID** | [**number**] | The unique ID of the Ezsigntemplateannotation | defaults to undefined|


### Return type

**EzsigntemplateannotationEditObjectV1Response**

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

# **ezsigntemplateannotationGetObjectV2**
> EzsigntemplateannotationGetObjectV2Response ezsigntemplateannotationGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplateannotationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateannotationApi(configuration);

let pkiEzsigntemplateannotationID: number; //The unique ID of the Ezsigntemplateannotation (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateannotationGetObjectV2(
    pkiEzsigntemplateannotationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateannotationID** | [**number**] | The unique ID of the Ezsigntemplateannotation | defaults to undefined|


### Return type

**EzsigntemplateannotationGetObjectV2Response**

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

