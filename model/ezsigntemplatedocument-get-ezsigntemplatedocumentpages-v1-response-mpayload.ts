/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplatedocumentpageResponseCompound } from './ezsigntemplatedocumentpage-response-compound';

/**
 * Payload for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatedocumentpages
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload
 */
export interface EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigntemplatedocumentpageResponseCompound>}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload
     */
    'a_objEzsigntemplatedocumentpage': Array<EzsigntemplatedocumentpageResponseCompound>;
}

