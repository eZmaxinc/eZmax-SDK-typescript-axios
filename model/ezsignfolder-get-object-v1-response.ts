/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponse } from './common-response';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
import { EzsignfolderGetObjectV1ResponseAllOf } from './ezsignfolder-get-object-v1-response-all-of';
import { EzsignfolderGetObjectV1ResponseMPayload } from './ezsignfolder-get-object-v1-response-mpayload';



/**
 * Response for the /1/object/ezsignfolder/getObject API Request
 * @export
 * @interface EzsignfolderGetObjectV1Response
 */
export interface EzsignfolderGetObjectV1Response {
    /**
     * 
     * @type {EzsignfolderGetObjectV1ResponseMPayload}
     * @memberof EzsignfolderGetObjectV1Response
     */
    mPayload: EzsignfolderGetObjectV1ResponseMPayload;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetObjectV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetObjectV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
