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
import { EzsigntemplatepackageRequestCompound } from './ezsigntemplatepackage-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}
 * @export
 * @interface EzsigntemplatepackageEditObjectV1Request
 */
export interface EzsigntemplatepackageEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatepackageRequestCompound}
     * @memberof EzsigntemplatepackageEditObjectV1Request
     */
    'objEzsigntemplatepackage': EzsigntemplatepackageRequestCompound;
}
/**
 * A EzsigntemplatepackageEditObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageEditObjectV1Request
 */
export class DefaultObjectEzsigntemplatepackageEditObjectV1Request extends DefaultObject {
   objEzsigntemplatepackage:Partial<EzsigntemplatepackageRequestCompound> = {}
}


