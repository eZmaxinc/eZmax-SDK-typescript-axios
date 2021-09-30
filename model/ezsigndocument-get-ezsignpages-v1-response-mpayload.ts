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


import { EzsignpageResponse } from './ezsignpage-response';



/**
 * Payload for the /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignpages API Request
 * @export
 * @interface EzsigndocumentGetEzsignpagesV1ResponseMPayload
 */
export interface EzsigndocumentGetEzsignpagesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignpageResponse>}
     * @memberof EzsigndocumentGetEzsignpagesV1ResponseMPayload
     */
    a_objEzsignpage: Array<EzsignpageResponse>;
}