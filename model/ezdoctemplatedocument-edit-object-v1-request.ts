/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzdoctemplatedocumentRequestCompound } from './ezdoctemplatedocument-request-compound';

/**
 * Request for PUT /1/object/ezdoctemplatedocument/{pkiEzdoctemplatedocumentID}
 * @export
 * @interface EzdoctemplatedocumentEditObjectV1Request
 */
export interface EzdoctemplatedocumentEditObjectV1Request {
    /**
     * 
     * @type {EzdoctemplatedocumentRequestCompound}
     * @memberof EzdoctemplatedocumentEditObjectV1Request
     */
    /*'objEzdoctemplatedocument': EzdoctemplatedocumentRequestCompound;*/
    'objEzdoctemplatedocument': EzdoctemplatedocumentRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzdoctemplatedocumentRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzdoctemplatedocumentRequestCompound } from './'

/**
 * @export 
 * A EzdoctemplatedocumentEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentEditObjectV1Request
 */
export class DataObjectEzdoctemplatedocumentEditObjectV1Request {
   objEzdoctemplatedocument:EzdoctemplatedocumentRequestCompound = new DataObjectEzdoctemplatedocumentRequestCompound()
}

/**
 * @export 
 * A EzdoctemplatedocumentEditObjectV1Request Validation Object
 * @class ValidationObjectEzdoctemplatedocumentEditObjectV1Request
 */
export class ValidationObjectEzdoctemplatedocumentEditObjectV1Request {
   objEzdoctemplatedocument = new ValidationObjectEzdoctemplatedocumentRequestCompound()
} 


