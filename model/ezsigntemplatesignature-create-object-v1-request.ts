/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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
 * Request for POST /1/object/ezsigntemplatesignature
 * @export
 * @interface EzsigntemplatesignatureCreateObjectV1Request
 */
export interface EzsigntemplatesignatureCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatesignatureRequestCompound>}
     * @memberof EzsigntemplatesignatureCreateObjectV1Request
     */
    'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureRequestCompound>;
}
/**
 * A EzsigntemplatesignatureCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignatureCreateObjectV1Request
 */
export class DefaultObjectEzsigntemplatesignatureCreateObjectV1Request extends DefaultObject {
   a_objEzsigntemplatesignature:Array<EzsigntemplatesignatureRequestCompound> = []
}


