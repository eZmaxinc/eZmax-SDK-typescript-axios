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


import { EzsignfolderRequestCompound } from './ezsignfolder-request-compound';

/**
 * Request for PUT /1/object/ezsignfolder/{pkiEzsignfolderID}
 * @export
 * @interface EzsignfolderEditObjectV1Request
 */
export interface EzsignfolderEditObjectV1Request {
    /**
     * 
     * @type {EzsignfolderRequestCompound}
     * @memberof EzsignfolderEditObjectV1Request
     */
    'objEzsignfolder': EzsignfolderRequestCompound;
}

