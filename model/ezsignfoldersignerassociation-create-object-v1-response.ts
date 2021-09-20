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
import { EzsignfoldersignerassociationCreateObjectV1ResponseAllOf } from './ezsignfoldersignerassociation-create-object-v1-response-all-of';
import { EzsignfoldersignerassociationCreateObjectV1ResponseMPayload } from './ezsignfoldersignerassociation-create-object-v1-response-mpayload';



/**
 * Response for the /1/object/ezsignfoldersignerassociation/createObject API Request
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1Response
 */
export interface EzsignfoldersignerassociationCreateObjectV1Response {
    /**
     * 
     * @type {EzsignfoldersignerassociationCreateObjectV1ResponseMPayload}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Response
     */
    mPayload: EzsignfoldersignerassociationCreateObjectV1ResponseMPayload;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
