# ObjectEzsignsignatureApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignsignatureCreateObjectV1**](#ezsignsignaturecreateobjectv1) | **POST** /1/object/ezsignsignature | Create a new Ezsignsignature|
|[**ezsignsignatureCreateObjectV2**](#ezsignsignaturecreateobjectv2) | **POST** /2/object/ezsignsignature | Create a new Ezsignsignature|
|[**ezsignsignatureCreateObjectV3**](#ezsignsignaturecreateobjectv3) | **POST** /3/object/ezsignsignature | Create a new Ezsignsignature|
|[**ezsignsignatureCreateObjectV4**](#ezsignsignaturecreateobjectv4) | **POST** /4/object/ezsignsignature | Create a new Ezsignsignature|
|[**ezsignsignatureDeleteObjectV1**](#ezsignsignaturedeleteobjectv1) | **DELETE** /1/object/ezsignsignature/{pkiEzsignsignatureID} | Delete an existing Ezsignsignature|
|[**ezsignsignatureEditObjectV3**](#ezsignsignatureeditobjectv3) | **PUT** /3/object/ezsignsignature/{pkiEzsignsignatureID} | Edit an existing Ezsignsignature|
|[**ezsignsignatureGetEzsignsignatureattachmentV1**](#ezsignsignaturegetezsignsignatureattachmentv1) | **GET** /1/object/ezsignsignature/{pkiEzsignsignatureID}/getEzsignsignatureattachment | Retrieve an existing Ezsignsignature\&#39;s Ezsignsignatureattachments|
|[**ezsignsignatureGetEzsignsignaturesAutomaticV1**](#ezsignsignaturegetezsignsignaturesautomaticv1) | **GET** /1/object/ezsignsignature/getEzsignsignaturesAutomatic | Retrieve all automatic Ezsignsignatures|
|[**ezsignsignatureGetObjectV4**](#ezsignsignaturegetobjectv4) | **GET** /4/object/ezsignsignature/{pkiEzsignsignatureID} | Retrieve an existing Ezsignsignature|
|[**ezsignsignatureSignV1**](#ezsignsignaturesignv1) | **POST** /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign | Sign the Ezsignsignature|

# **ezsignsignatureCreateObjectV1**
> EzsignsignatureCreateObjectV1Response ezsignsignatureCreateObjectV1(ezsignsignatureCreateObjectV1Request)

The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let ezsignsignatureCreateObjectV1Request: Array<EzsignsignatureCreateObjectV1Request>; //

const { status, data } = await apiInstance.ezsignsignatureCreateObjectV1(
    ezsignsignatureCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureCreateObjectV1Request** | **Array<EzsignsignatureCreateObjectV1Request>**|  | |


### Return type

**EzsignsignatureCreateObjectV1Response**

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

# **ezsignsignatureCreateObjectV2**
> EzsignsignatureCreateObjectV2Response ezsignsignatureCreateObjectV2(ezsignsignatureCreateObjectV2Request)

The endpoint allows to create one or many elements at once.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration,
    EzsignsignatureCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let ezsignsignatureCreateObjectV2Request: EzsignsignatureCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsignsignatureCreateObjectV2(
    ezsignsignatureCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureCreateObjectV2Request** | **EzsignsignatureCreateObjectV2Request**|  | |


### Return type

**EzsignsignatureCreateObjectV2Response**

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

# **ezsignsignatureCreateObjectV3**
> EzsignsignatureCreateObjectV3Response ezsignsignatureCreateObjectV3(ezsignsignatureCreateObjectV3Request)

The endpoint allows to create one or many elements at once.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration,
    EzsignsignatureCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let ezsignsignatureCreateObjectV3Request: EzsignsignatureCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsignsignatureCreateObjectV3(
    ezsignsignatureCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureCreateObjectV3Request** | **EzsignsignatureCreateObjectV3Request**|  | |


### Return type

**EzsignsignatureCreateObjectV3Response**

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

# **ezsignsignatureCreateObjectV4**
> EzsignsignatureCreateObjectV4Response ezsignsignatureCreateObjectV4(ezsignsignatureCreateObjectV4Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration,
    EzsignsignatureCreateObjectV4Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let ezsignsignatureCreateObjectV4Request: EzsignsignatureCreateObjectV4Request; //

const { status, data } = await apiInstance.ezsignsignatureCreateObjectV4(
    ezsignsignatureCreateObjectV4Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureCreateObjectV4Request** | **EzsignsignatureCreateObjectV4Request**|  | |


### Return type

**EzsignsignatureCreateObjectV4Response**

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

# **ezsignsignatureDeleteObjectV1**
> EzsignsignatureDeleteObjectV1Response ezsignsignatureDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let pkiEzsignsignatureID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignsignatureDeleteObjectV1(
    pkiEzsignsignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignatureDeleteObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignsignatureEditObjectV3**
> EzsignsignatureEditObjectV3Response ezsignsignatureEditObjectV3(ezsignsignatureEditObjectV3Request)



### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration,
    EzsignsignatureEditObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let pkiEzsignsignatureID: number; // (default to undefined)
let ezsignsignatureEditObjectV3Request: EzsignsignatureEditObjectV3Request; //

const { status, data } = await apiInstance.ezsignsignatureEditObjectV3(
    pkiEzsignsignatureID,
    ezsignsignatureEditObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureEditObjectV3Request** | **EzsignsignatureEditObjectV3Request**|  | |
| **pkiEzsignsignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignatureEditObjectV3Response**

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

# **ezsignsignatureGetEzsignsignatureattachmentV1**
> EzsignsignatureGetEzsignsignatureattachmentV1Response ezsignsignatureGetEzsignsignatureattachmentV1()


### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let pkiEzsignsignatureID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignsignatureGetEzsignsignatureattachmentV1(
    pkiEzsignsignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignatureGetEzsignsignatureattachmentV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignsignatureGetEzsignsignaturesAutomaticV1**
> EzsignsignatureGetEzsignsignaturesAutomaticV1Response ezsignsignatureGetEzsignsignaturesAutomaticV1()

Return all the Ezsignsignatures that can be signed by the current user

### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

const { status, data } = await apiInstance.ezsignsignatureGetEzsignsignaturesAutomaticV1();
```

### Parameters
This endpoint does not have any parameters.


### Return type

**EzsignsignatureGetEzsignsignaturesAutomaticV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignsignatureGetObjectV4**
> EzsignsignatureGetObjectV4Response ezsignsignatureGetObjectV4()



### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let pkiEzsignsignatureID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignsignatureGetObjectV4(
    pkiEzsignsignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignatureGetObjectV4Response**

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

# **ezsignsignatureSignV1**
> EzsignsignatureSignV1Response ezsignsignatureSignV1(ezsignsignatureSignV1Request)



### Example

```typescript
import {
    ObjectEzsignsignatureApi,
    Configuration,
    EzsignsignatureSignV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignatureApi(configuration);

let pkiEzsignsignatureID: number; // (default to undefined)
let ezsignsignatureSignV1Request: EzsignsignatureSignV1Request; //

const { status, data } = await apiInstance.ezsignsignatureSignV1(
    pkiEzsignsignatureID,
    ezsignsignatureSignV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignatureSignV1Request** | **EzsignsignatureSignV1Request**|  | |
| **pkiEzsignsignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignatureSignV1Response**

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

