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



/**
 * Response for the /1/object/ezsignfolder/deleteObject API Request
 * @export
 * @interface EzsignfolderDeleteObjectV1Response
 */
export interface EzsignfolderDeleteObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderDeleteObjectV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderDeleteObjectV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
