/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplatesignatureResponseCompound } from './ezsigntemplatesignature-response-compound';

/**
 * Payload for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocument}/getEzsigntemplatesignatures
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
 */
export interface EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigntemplatesignatureResponseCompound>}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
     */
    'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureResponseCompound>;
}

