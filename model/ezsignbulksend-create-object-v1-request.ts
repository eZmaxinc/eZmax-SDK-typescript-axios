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


import { EzsignbulksendRequestCompound } from './ezsignbulksend-request-compound';

/**
 * Request for POST /1/object/ezsignbulksend
 * @export
 * @interface EzsignbulksendCreateObjectV1Request
 */
export interface EzsignbulksendCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignbulksendRequestCompound>}
     * @memberof EzsignbulksendCreateObjectV1Request
     */
    'a_objEzsignbulksend': Array<EzsignbulksendRequestCompound>;
}
