/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload } from './ezdoctemplatefieldtypecategory-get-autocomplete-v2-response-mpayload';

/**
 * @type EzdoctemplatefieldtypecategoryGetAutocompleteV2Response
 * Response for GET /2/object/ezdoctemplatefieldtypecategory/getAutocomplete
 * @export
 */
/*export type EzdoctemplatefieldtypecategoryGetAutocompleteV2Response = CommonResponse;*/
export interface EzdoctemplatefieldtypecategoryGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzdoctemplatefieldtypecategoryGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzdoctemplatefieldtypecategoryGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload}
     * @memberof EzdoctemplatefieldtypecategoryGetAutocompleteV2Response
     */
    mPayload:EzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A EzdoctemplatefieldtypecategoryGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2Response
 */
export class DataObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload = new DataObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A EzdoctemplatefieldtypecategoryGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2Response
 */
export class ValidationObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzdoctemplatefieldtypecategoryGetAutocompleteV2ResponseMPayload()
} 


