/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageRequestCompound } from './ezsigntemplatepackage-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsigntemplatepackage
 * @export
 * @interface EzsigntemplatepackageCreateObjectV1Request
 */
export interface EzsigntemplatepackageCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatepackageRequestCompound>}
     * @memberof EzsigntemplatepackageCreateObjectV1Request
     */
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageRequestCompound>;
}
/**
 * A EzsigntemplatepackageCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageCreateObjectV1Request
 */
export class DefaultObjectEzsigntemplatepackageCreateObjectV1Request extends DefaultObject {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageRequestCompound> = []
}


