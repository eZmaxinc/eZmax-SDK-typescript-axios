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
import { EzsigndocumentGetDownloadUrlV1ResponseAllOf } from './ezsigndocument-get-download-url-v1-response-all-of';
import { EzsigndocumentGetDownloadUrlV1ResponseMPayload } from './ezsigndocument-get-download-url-v1-response-mpayload';



/**
 * Response for the /1/object/ezsigndocument/{pkiEzsigndocument}/getDownloadUrl API Request
 * @export
 * @interface EzsigndocumentGetDownloadUrlV1Response
 */
export interface EzsigndocumentGetDownloadUrlV1Response {
    /**
     * 
     * @type {EzsigndocumentGetDownloadUrlV1ResponseMPayload}
     * @memberof EzsigndocumentGetDownloadUrlV1Response
     */
    mPayload: EzsigndocumentGetDownloadUrlV1ResponseMPayload;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentGetDownloadUrlV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentGetDownloadUrlV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
