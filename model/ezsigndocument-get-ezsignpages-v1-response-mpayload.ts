/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignpageResponseCompound } from './ezsignpage-response-compound';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignpages
 * @export
 * @interface EzsigndocumentGetEzsignpagesV1ResponseMPayload
 */
export interface EzsigndocumentGetEzsignpagesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignpageResponseCompound>}
     * @memberof EzsigndocumentGetEzsignpagesV1ResponseMPayload
     */
    'a_objEzsignpage': Array<EzsignpageResponseCompound>;
}

