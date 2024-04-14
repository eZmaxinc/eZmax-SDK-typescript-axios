/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerGetObjectV2ResponseMPayload } from './ezsigntemplatepackagesigner-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplatepackagesignerGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 */
/*export type EzsigntemplatepackagesignerGetObjectV2Response = CommonResponse;*/
export interface EzsigntemplatepackagesignerGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepackagesignerGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepackagesignerGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepackagesignerGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatepackagesignerGetObjectV2Response
     */
    mPayload:EzsigntemplatepackagesignerGetObjectV2ResponseMPayload 
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
import { DataObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignerGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerGetObjectV2Response
 */
export class DataObjectEzsigntemplatepackagesignerGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackagesignerGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignerGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerGetObjectV2Response
 */
export class ValidationObjectEzsigntemplatepackagesignerGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackagesignerGetObjectV2ResponseMPayload()
} 


