# ObjectEzsigntemplatesignerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatesignerCreateObjectV1**](#ezsigntemplatesignercreateobjectv1) | **POST** /1/object/ezsigntemplatesigner | Create a new Ezsigntemplatesigner|
|[**ezsigntemplatesignerCreateObjectV2**](#ezsigntemplatesignercreateobjectv2) | **POST** /2/object/ezsigntemplatesigner | Create a new Ezsigntemplatesigner|
|[**ezsigntemplatesignerDeleteObjectV1**](#ezsigntemplatesignerdeleteobjectv1) | **DELETE** /1/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID} | Delete an existing Ezsigntemplatesigner|
|[**ezsigntemplatesignerEditObjectV1**](#ezsigntemplatesignereditobjectv1) | **PUT** /1/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID} | Edit an existing Ezsigntemplatesigner|
|[**ezsigntemplatesignerEditObjectV2**](#ezsigntemplatesignereditobjectv2) | **PUT** /2/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID} | Edit an existing Ezsigntemplatesigner|
|[**ezsigntemplatesignerGetObjectV2**](#ezsigntemplatesignergetobjectv2) | **GET** /2/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID} | Retrieve an existing Ezsigntemplatesigner|
|[**ezsigntemplatesignerGetObjectV3**](#ezsigntemplatesignergetobjectv3) | **GET** /3/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID} | Retrieve an existing Ezsigntemplatesigner|

# **ezsigntemplatesignerCreateObjectV1**
> EzsigntemplatesignerCreateObjectV1Response ezsigntemplatesignerCreateObjectV1(ezsigntemplatesignerCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration,
    EzsigntemplatesignerCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let ezsigntemplatesignerCreateObjectV1Request: EzsigntemplatesignerCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatesignerCreateObjectV1(
    ezsigntemplatesignerCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignerCreateObjectV1Request** | **EzsigntemplatesignerCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatesignerCreateObjectV1Response**

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

# **ezsigntemplatesignerCreateObjectV2**
> EzsigntemplatesignerCreateObjectV2Response ezsigntemplatesignerCreateObjectV2(ezsigntemplatesignerCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration,
    EzsigntemplatesignerCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let ezsigntemplatesignerCreateObjectV2Request: EzsigntemplatesignerCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsigntemplatesignerCreateObjectV2(
    ezsigntemplatesignerCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignerCreateObjectV2Request** | **EzsigntemplatesignerCreateObjectV2Request**|  | |


### Return type

**EzsigntemplatesignerCreateObjectV2Response**

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

# **ezsigntemplatesignerDeleteObjectV1**
> EzsigntemplatesignerDeleteObjectV1Response ezsigntemplatesignerDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let pkiEzsigntemplatesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatesignerDeleteObjectV1(
    pkiEzsigntemplatesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignerDeleteObjectV1Response**

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

# **ezsigntemplatesignerEditObjectV1**
> EzsigntemplatesignerEditObjectV1Response ezsigntemplatesignerEditObjectV1(ezsigntemplatesignerEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration,
    EzsigntemplatesignerEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let pkiEzsigntemplatesignerID: number; // (default to undefined)
let ezsigntemplatesignerEditObjectV1Request: EzsigntemplatesignerEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatesignerEditObjectV1(
    pkiEzsigntemplatesignerID,
    ezsigntemplatesignerEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignerEditObjectV1Request** | **EzsigntemplatesignerEditObjectV1Request**|  | |
| **pkiEzsigntemplatesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignerEditObjectV1Response**

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

# **ezsigntemplatesignerEditObjectV2**
> EzsigntemplatesignerEditObjectV2Response ezsigntemplatesignerEditObjectV2(ezsigntemplatesignerEditObjectV2Request)



### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration,
    EzsigntemplatesignerEditObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let pkiEzsigntemplatesignerID: number; // (default to undefined)
let ezsigntemplatesignerEditObjectV2Request: EzsigntemplatesignerEditObjectV2Request; //

const { status, data } = await apiInstance.ezsigntemplatesignerEditObjectV2(
    pkiEzsigntemplatesignerID,
    ezsigntemplatesignerEditObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignerEditObjectV2Request** | **EzsigntemplatesignerEditObjectV2Request**|  | |
| **pkiEzsigntemplatesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignerEditObjectV2Response**

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

# **ezsigntemplatesignerGetObjectV2**
> EzsigntemplatesignerGetObjectV2Response ezsigntemplatesignerGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let pkiEzsigntemplatesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatesignerGetObjectV2(
    pkiEzsigntemplatesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignerGetObjectV2Response**

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

# **ezsigntemplatesignerGetObjectV3**
> EzsigntemplatesignerGetObjectV3Response ezsigntemplatesignerGetObjectV3()



### Example

```typescript
import {
    ObjectEzsigntemplatesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignerApi(configuration);

let pkiEzsigntemplatesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatesignerGetObjectV3(
    pkiEzsigntemplatesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignerGetObjectV3Response**

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

