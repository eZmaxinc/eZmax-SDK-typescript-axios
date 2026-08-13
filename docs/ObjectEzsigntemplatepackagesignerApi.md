# ObjectEzsigntemplatepackagesignerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatepackagesignerCreateObjectV1**](#ezsigntemplatepackagesignercreateobjectv1) | **POST** /1/object/ezsigntemplatepackagesigner | Create a new Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerCreateObjectV2**](#ezsigntemplatepackagesignercreateobjectv2) | **POST** /2/object/ezsigntemplatepackagesigner | Create a new Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerDeleteObjectV1**](#ezsigntemplatepackagesignerdeleteobjectv1) | **DELETE** /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID} | Delete an existing Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerEditObjectV1**](#ezsigntemplatepackagesignereditobjectv1) | **PUT** /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID} | Edit an existing Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerEditObjectV2**](#ezsigntemplatepackagesignereditobjectv2) | **PUT** /2/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID} | Edit an existing Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerGetObjectV2**](#ezsigntemplatepackagesignergetobjectv2) | **GET** /2/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID} | Retrieve an existing Ezsigntemplatepackagesigner|
|[**ezsigntemplatepackagesignerGetObjectV3**](#ezsigntemplatepackagesignergetobjectv3) | **GET** /3/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID} | Retrieve an existing Ezsigntemplatepackagesigner|

# **ezsigntemplatepackagesignerCreateObjectV1**
> EzsigntemplatepackagesignerCreateObjectV1Response ezsigntemplatepackagesignerCreateObjectV1(ezsigntemplatepackagesignerCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration,
    EzsigntemplatepackagesignerCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let ezsigntemplatepackagesignerCreateObjectV1Request: EzsigntemplatepackagesignerCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagesignerCreateObjectV1(
    ezsigntemplatepackagesignerCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagesignerCreateObjectV1Request** | **EzsigntemplatepackagesignerCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatepackagesignerCreateObjectV1Response**

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

# **ezsigntemplatepackagesignerCreateObjectV2**
> EzsigntemplatepackagesignerCreateObjectV2Response ezsigntemplatepackagesignerCreateObjectV2(ezsigntemplatepackagesignerCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration,
    EzsigntemplatepackagesignerCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let ezsigntemplatepackagesignerCreateObjectV2Request: EzsigntemplatepackagesignerCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagesignerCreateObjectV2(
    ezsigntemplatepackagesignerCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagesignerCreateObjectV2Request** | **EzsigntemplatepackagesignerCreateObjectV2Request**|  | |


### Return type

**EzsigntemplatepackagesignerCreateObjectV2Response**

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

# **ezsigntemplatepackagesignerDeleteObjectV1**
> EzsigntemplatepackagesignerDeleteObjectV1Response ezsigntemplatepackagesignerDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let pkiEzsigntemplatepackagesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagesignerDeleteObjectV1(
    pkiEzsigntemplatepackagesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignerDeleteObjectV1Response**

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

# **ezsigntemplatepackagesignerEditObjectV1**
> EzsigntemplatepackagesignerEditObjectV1Response ezsigntemplatepackagesignerEditObjectV1(ezsigntemplatepackagesignerEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration,
    EzsigntemplatepackagesignerEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let pkiEzsigntemplatepackagesignerID: number; // (default to undefined)
let ezsigntemplatepackagesignerEditObjectV1Request: EzsigntemplatepackagesignerEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagesignerEditObjectV1(
    pkiEzsigntemplatepackagesignerID,
    ezsigntemplatepackagesignerEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagesignerEditObjectV1Request** | **EzsigntemplatepackagesignerEditObjectV1Request**|  | |
| **pkiEzsigntemplatepackagesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignerEditObjectV1Response**

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

# **ezsigntemplatepackagesignerEditObjectV2**
> EzsigntemplatepackagesignerEditObjectV2Response ezsigntemplatepackagesignerEditObjectV2(ezsigntemplatepackagesignerEditObjectV2Request)



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration,
    EzsigntemplatepackagesignerEditObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let pkiEzsigntemplatepackagesignerID: number; // (default to undefined)
let ezsigntemplatepackagesignerEditObjectV2Request: EzsigntemplatepackagesignerEditObjectV2Request; //

const { status, data } = await apiInstance.ezsigntemplatepackagesignerEditObjectV2(
    pkiEzsigntemplatepackagesignerID,
    ezsigntemplatepackagesignerEditObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackagesignerEditObjectV2Request** | **EzsigntemplatepackagesignerEditObjectV2Request**|  | |
| **pkiEzsigntemplatepackagesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignerEditObjectV2Response**

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

# **ezsigntemplatepackagesignerGetObjectV2**
> EzsigntemplatepackagesignerGetObjectV2Response ezsigntemplatepackagesignerGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let pkiEzsigntemplatepackagesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagesignerGetObjectV2(
    pkiEzsigntemplatepackagesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignerGetObjectV2Response**

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

# **ezsigntemplatepackagesignerGetObjectV3**
> EzsigntemplatepackagesignerGetObjectV3Response ezsigntemplatepackagesignerGetObjectV3()



### Example

```typescript
import {
    ObjectEzsigntemplatepackagesignerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackagesignerApi(configuration);

let pkiEzsigntemplatepackagesignerID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackagesignerGetObjectV3(
    pkiEzsigntemplatepackagesignerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackagesignerID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackagesignerGetObjectV3Response**

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

