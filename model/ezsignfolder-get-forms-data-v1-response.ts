/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponse } from './common-response';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
import { EzsignfolderGetFormsDataV1ResponseAllOf } from './ezsignfolder-get-forms-data-v1-response-all-of';
import { EzsignfolderGetFormsDataV1ResponseMPayload } from './ezsignfolder-get-forms-data-v1-response-mpayload';



/**
 * Response for the /1/object/ezsignfolder/{pkiEzsignfolder}/getFormsData API Request
 * @export
 * @interface EzsignfolderGetFormsDataV1Response
 */
export interface EzsignfolderGetFormsDataV1Response {
    /**
     * 
     * @type {EzsignfolderGetFormsDataV1ResponseMPayload}
     * @memberof EzsignfolderGetFormsDataV1Response
     */
    mPayload: EzsignfolderGetFormsDataV1ResponseMPayload;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetFormsDataV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetFormsDataV1Response
     */
    objDebug?: CommonResponseObjDebug;
}