/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureRequestCompound } from './ezsigntemplatesignature-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 * @interface EzsigntemplatesignatureEditObjectV1Request
 */
export interface EzsigntemplatesignatureEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatesignatureRequestCompound}
     * @memberof EzsigntemplatesignatureEditObjectV1Request
     */
    'objEzsigntemplatesignature': EzsigntemplatesignatureRequestCompound;
}
/**
 * A EzsigntemplatesignatureEditObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignatureEditObjectV1Request
 */
export class DefaultObjectEzsigntemplatesignatureEditObjectV1Request extends DefaultObject {
   objEzsigntemplatesignature:Partial<EzsigntemplatesignatureRequestCompound> = {}
}


