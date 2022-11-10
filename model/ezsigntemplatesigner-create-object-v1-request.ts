/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerRequestCompound } from './ezsigntemplatesigner-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsigntemplatesigner
 * @export
 * @interface EzsigntemplatesignerCreateObjectV1Request
 */
export interface EzsigntemplatesignerCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatesignerRequestCompound>}
     * @memberof EzsigntemplatesignerCreateObjectV1Request
     */
    'a_objEzsigntemplatesigner': Array<EzsigntemplatesignerRequestCompound>;
}
/**
 * A EzsigntemplatesignerCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerCreateObjectV1Request
 */
export class DefaultObjectEzsigntemplatesignerCreateObjectV1Request extends DefaultObject {
   a_objEzsigntemplatesigner:Array<EzsigntemplatesignerRequestCompound> = []
}


