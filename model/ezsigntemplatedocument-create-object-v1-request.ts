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


import { EzsigntemplatedocumentRequestCompound } from './ezsigntemplatedocument-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatedocument
 * @export
 * @interface EzsigntemplatedocumentCreateObjectV1Request
 */
export interface EzsigntemplatedocumentCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatedocumentRequestCompound>}
     * @memberof EzsigntemplatedocumentCreateObjectV1Request
     */
    'a_objEzsigntemplatedocument': Array<EzsigntemplatedocumentRequestCompound>;
}

