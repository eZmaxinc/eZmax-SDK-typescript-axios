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


import { EzsigndocumentRequestCompound } from './ezsigndocument-request-compound';

/**
 * Request for POST /2/object/ezsigndocument
 * @export
 * @interface EzsigndocumentCreateObjectV2Request
 */
export interface EzsigndocumentCreateObjectV2Request {
    /**
     * 
     * @type {Array<EzsigndocumentRequestCompound>}
     * @memberof EzsigndocumentCreateObjectV2Request
     */
    'a_objEzsigndocument': Array<EzsigndocumentRequestCompound>;
}

