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


import { EzsigntemplateRequestCompound } from './ezsigntemplate-request-compound';

/**
 * Request for POST /1/object/ezsigntemplate
 * @export
 * @interface EzsigntemplateCreateObjectV1Request
 */
export interface EzsigntemplateCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplateRequestCompound>}
     * @memberof EzsigntemplateCreateObjectV1Request
     */
    'a_objEzsigntemplate': Array<EzsigntemplateRequestCompound>;
}

