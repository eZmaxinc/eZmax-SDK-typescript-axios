/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.47
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponse } from './common-response';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
import { EzsignfoldersignerassociationGetObjectV1ResponseAllOf } from './ezsignfoldersignerassociation-get-object-v1-response-all-of';



/**
 * Response for the /1/object/ezsignfoldersignerassociation/getObject API Request
 * @export
 * @interface EzsignfoldersignerassociationGetObjectV1Response
 */
export interface EzsignfoldersignerassociationGetObjectV1Response {
    /**
     * Payload for the /1/object/ezsignfoldersignerassociation/getObject API Request
     * @type {object}
     * @memberof EzsignfoldersignerassociationGetObjectV1Response
     */
    mPayload: object;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldersignerassociationGetObjectV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldersignerassociationGetObjectV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
